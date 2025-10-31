import { createCipheriv, createDecipheriv, randomBytes } from 'crypto'
import {
  KMSClient,
  DecryptCommand,
  GenerateDataKeyCommand,
} from '@aws-sdk/client-kms'

const V1 = 'v1'
const V2 = 'v2'

type AAD = Record<string, string> | undefined

function aadBytes(aad: AAD): Buffer | undefined {
  if (!aad) return undefined
  const keys = Object.keys(aad).sort()
  const compactJson = `{${keys
    .map((k) => `${JSON.stringify(k)}:${JSON.stringify(aad[k]!)}`)
    .join(',')}}`
  return Buffer.from(compactJson)
}

interface KeyProvider {
  getActiveKey(): [kid: string, key: Buffer]
  getKeyById(kid: string): Buffer
}

class EnvKeyProvider implements KeyProvider {
  private key: Buffer
  private kid: string

  constructor() {
    const b64 = process.env.APP_DATA_KEY
    if (!b64)
      throw new Error('Missing APP_DATA_KEY (base64 32 bytes) in environment')
    const raw = Buffer.from(b64, 'base64')
    if (raw.length !== 32)
      throw new Error('APP_DATA_KEY must decode to exactly 32 bytes')
    this.key = raw
    this.kid = process.env.APP_DATA_KEY_ID || 'env-v1'
  }

  getActiveKey(): [string, Buffer] {
    return [this.kid, this.key]
  }

  getKeyById(kid: string): Buffer {
    if (kid !== this.kid) throw new Error(`Unknown KID: ${kid}`)
    return this.key
  }
}

class KMSProvider {
  private cmkId: string
  private client: KMSClient

  constructor(cmkEnv = 'KMS_KEY_ID', regionEnv = 'AWS_REGION') {
    const cmkId = process.env[cmkEnv]
    if (!cmkId) throw new Error(`Missing ${cmkEnv}`)
    this.cmkId = cmkId
    const region = process.env[regionEnv] || 'us-east-1'
    this.client = new KMSClient({ region })
  }

  async generateDataKey(): Promise<
    [kid: string, plaintext: Buffer, edk: Buffer]
  > {
    const res = await this.client.send(
      new GenerateDataKeyCommand({ KeyId: this.cmkId, KeySpec: 'AES_256' }),
    )
    if (!res.Plaintext || !res.CiphertextBlob)
      throw new Error('KMS generateDataKey returned empty values')
    return [
      this.cmkId,
      Buffer.from(res.Plaintext as Uint8Array),
      Buffer.from(res.CiphertextBlob as Uint8Array),
    ]
  }

  async decryptDataKey(edk: Buffer): Promise<Buffer> {
    const res = await this.client.send(
      new DecryptCommand({ CiphertextBlob: edk, KeyId: this.cmkId }),
    )
    if (!res.Plaintext) throw new Error('KMS decrypt returned empty plaintext')
    return Buffer.from(res.Plaintext as Uint8Array)
  }
}

function encryptV1(
  aesKey: Buffer,
  kid: string,
  plaintext: string,
  aad?: Record<string, string>,
): string {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', aesKey, nonce)
  const aadBuf = aadBytes(aad)
  if (aadBuf) cipher.setAAD(aadBuf)
  const enc = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final(),
  ])
  const tag = cipher.getAuthTag()
  const ct = Buffer.concat([enc, tag])

  const kidBytes = Buffer.from(kid, 'utf8')
  if (kidBytes.length > 255) throw new Error('kid too long')
  const header = Buffer.concat([
    Buffer.from(V1, 'utf8'),
    Buffer.from([kidBytes.length]),
    kidBytes,
  ])
  const blob = Buffer.concat([header, nonce, ct])
  return blob.toString('base64')
}

function decryptV1(
  kp: KeyProvider,
  blobB64: string,
  aad?: Record<string, string>,
): [kid: string, plaintext: string] {
  const raw = Buffer.from(blobB64, 'base64')
  if (raw.length < 2 + 1 + 12 + 16) throw new Error('blob too short')
  const version = raw.subarray(0, 2).toString('utf8')
  if (version !== V1) throw new Error(`Unsupported version: ${version}`)
  const kidLen = raw[2]
  let off = 3
  const kid = raw.subarray(off, off + kidLen).toString('utf8')
  off += kidLen
  const nonce = raw.subarray(off, off + 12)
  off += 12
  const ct = raw.subarray(off)
  if (ct.length < 16) throw new Error('ciphertext too short')
  const data = ct.subarray(0, ct.length - 16)
  const tag = ct.subarray(ct.length - 16)

  const key = kp.getKeyById(kid)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  const aadBuf = aadBytes(aad)
  if (aadBuf) decipher.setAAD(aadBuf)
  decipher.setAuthTag(tag)
  const dec = Buffer.concat([decipher.update(data), decipher.final()])
  return [kid, dec.toString('utf8')]
}

async function encryptV2WithKms(
  kms: KMSProvider,
  plaintext: string,
  aad?: Record<string, string>,
): Promise<string> {
  const [kid, dataKey, edk] = await kms.generateDataKey()
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', dataKey, nonce)
  const aadBuf = aadBytes(aad)
  if (aadBuf) cipher.setAAD(aadBuf)
  const enc = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final(),
  ])
  const tag = cipher.getAuthTag()
  const ct = Buffer.concat([enc, tag])

  const kidBytes = Buffer.from(kid, 'utf8')
  if (kidBytes.length > 255) throw new Error('kid too long')
  const edkLen = Buffer.alloc(2)
  edkLen.writeUInt16BE(edk.length, 0)
  const header = Buffer.concat([
    Buffer.from(V2, 'utf8'),
    Buffer.from([kidBytes.length]),
    kidBytes,
    edkLen,
    edk,
  ])
  const blob = Buffer.concat([header, nonce, ct])
  return blob.toString('base64')
}

async function decryptV2WithKms(
  kms: KMSProvider,
  blobB64: string,
  aad?: Record<string, string>,
): Promise<[kid: string, plaintext: string]> {
  const raw = Buffer.from(blobB64, 'base64')
  if (raw.length < 2 + 1 + 2 + 12 + 16) throw new Error('blob too short')
  const version = raw.subarray(0, 2).toString('utf8')
  if (version !== V2) throw new Error(`Unsupported version: ${version}`)
  const kidLen = raw[2]
  let off = 3
  const kid = raw.subarray(off, off + kidLen).toString('utf8')
  off += kidLen
  const edkLen = raw.readUInt16BE(off)
  off += 2
  const edk = raw.subarray(off, off + edkLen)
  off += edkLen
  const nonce = raw.subarray(off, off + 12)
  off += 12
  const ct = raw.subarray(off)
  if (ct.length < 16) throw new Error('ciphertext too short')
  const data = ct.subarray(0, ct.length - 16)
  const tag = ct.subarray(ct.length - 16)

  const dataKey = await kms.decryptDataKey(edk)
  const decipher = createDecipheriv('aes-256-gcm', dataKey, nonce)
  const aadBuf = aadBytes(aad)
  if (aadBuf) decipher.setAAD(aadBuf)
  decipher.setAuthTag(tag)
  const dec = Buffer.concat([decipher.update(data), decipher.final()])
  return [kid, dec.toString('utf8')]
}

export class EncryptionService {
  private modeValue: 'env' | 'kms'
  private envProvider: EnvKeyProvider | null
  private kmsProvider: KMSProvider | null

  constructor(mode?: string) {
    const m = (mode || process.env.ENC_MODE || 'env').toLowerCase()
    if (m !== 'env' && m !== 'kms')
      throw new Error("ENC_MODE must be 'env' or 'kms'")
    this.modeValue = m
    if (m === 'env') {
      this.envProvider = new EnvKeyProvider()
      this.kmsProvider = null
    } else {
      this.envProvider = null
      this.kmsProvider = new KMSProvider()
    }
  }

  get mode(): 'env' | 'kms' {
    return this.modeValue
  }

  async encryptText(
    plaintext: string,
    aad?: Record<string, string>,
  ): Promise<string> {
    if (this.modeValue === 'env') {
      const [kid, key] = this.envProvider!.getActiveKey()
      return encryptV1(key, kid, plaintext, aad || {})
    } else {
      return encryptV2WithKms(this.kmsProvider!, plaintext, aad || {})
    }
  }

  async decryptText(
    blobB64: string,
    aad?: Record<string, string>,
  ): Promise<string> {
    const raw = Buffer.from(blobB64, 'base64')
    // Inspect version but follow configured mode, mirroring Python behavior
    raw.subarray(0, 2).toString('utf8')
    if (this.modeValue === 'env') {
      const [, pt] = decryptV1(this.envProvider!, blobB64, aad || {})
      return pt
    } else {
      const [, pt] = await decryptV2WithKms(
        this.kmsProvider!,
        blobB64,
        aad || {},
      )
      return pt
    }
  }

  async encryptDict(
    config: Record<string, string | unknown>,
    aad: Record<string, string>,
  ): Promise<string> {
    const plaintext = JSON.stringify(config)
    return this.encryptText(plaintext, aad)
  }

  async decryptToDict(
    blobB64: string,
    aad: Record<string, string>,
  ): Promise<Record<string, unknown>> {
    const plaintext = await this.decryptText(blobB64, aad)
    return JSON.parse(plaintext)
  }

  static buildAadStatic(
    userEmail: string,
    serverName: string,
    appName: string,
    purpose = 'user-config',
  ): Record<string, string> {
    return {
      user_email: userEmail,
      server_name: serverName,
      app_name: appName,
      purpose,
    }
  }

  // Instance-accessible variant to satisfy interface contracts
  buildAad(
    userEmail: string,
    serverName: string,
    appName: string,
    purpose = 'user-config',
  ): Record<string, string> {
    return EncryptionService.buildAadStatic(
      userEmail,
      serverName,
      appName,
      purpose,
    )
  }
}
