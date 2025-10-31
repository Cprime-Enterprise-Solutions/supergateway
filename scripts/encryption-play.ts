#!/usr/bin/env -S node
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { readFileSync } from 'fs'
import { EncryptionService } from '../src/services/encryptionService.js'

type AAD = Record<string, string>

function parseAad(aadStr?: string): AAD | undefined {
  if (!aadStr) return undefined
  try {
    const obj = JSON.parse(aadStr)
    if (obj && typeof obj === 'object') return obj as AAD
  } catch (e) {
    throw new Error(`Invalid --aad JSON: ${(e as Error).message}`)
  }
  return undefined
}

async function main() {
  const argv = yargs(hideBin(process.argv))
    .scriptName('encryption-play')
    .usage('$0 <cmd> [args]')
    .command(
      'encrypt-text',
      'Encrypt a UTF-8 string and print base64 blob',
      (y) =>
        y
          .option('text', { type: 'string', describe: 'Plaintext to encrypt' })
          .option('file', {
            type: 'string',
            describe: 'Read plaintext from file',
          })
          .option('aad', {
            type: 'string',
            describe: 'AAD JSON, e.g. {"k":"v"}',
          })
          .option('mode', { type: 'string', choices: ['env', 'kms'] as const })
          .demandOption(['text'], 'Provide --text or --file')
          .conflicts('text', 'file'),
      async (args) => {
        const mode =
          (args.mode as string | undefined) || process.env.ENC_MODE || 'env'
        const svc = new EncryptionService(mode)
        const plaintext = args.file
          ? readFileSync(args.file as string, 'utf8')
          : (args.text as string)
        const aad = parseAad(args.aad as string | undefined)
        const blob = await svc.encryptText(plaintext, aad)
        console.log(blob)
      },
    )
    .command(
      'decrypt-text',
      'Decrypt a base64 blob and print plaintext',
      (y) =>
        y
          .option('blob', {
            type: 'string',
            demandOption: true,
            describe: 'Base64-encoded blob',
          })
          .option('aad', {
            type: 'string',
            describe: 'AAD JSON used on encrypt',
          })
          .option('mode', { type: 'string', choices: ['env', 'kms'] as const }),
      async (args) => {
        const mode =
          (args.mode as string | undefined) || process.env.ENC_MODE || 'env'
        const svc = new EncryptionService(mode)
        const aad = parseAad(args.aad as string | undefined)
        const pt = await svc.decryptText(args.blob as string, aad)
        console.log(pt)
      },
    )
    .command(
      'encrypt-json',
      'Encrypt JSON file or inline JSON and print base64 blob',
      (y) =>
        y
          .option('json', { type: 'string', describe: 'Inline JSON string' })
          .option('file', { type: 'string', describe: 'Read JSON from file' })
          .option('aad', {
            type: 'string',
            demandOption: true,
            describe: 'AAD JSON',
          })
          .option('mode', { type: 'string', choices: ['env', 'kms'] as const })
          .check((a) => {
            if (!a.json && !a.file) throw new Error('Provide --json or --file')
            if (a.json && a.file)
              throw new Error('Use only one of --json or --file')
            return true
          }),
      async (args) => {
        const mode =
          (args.mode as string | undefined) || process.env.ENC_MODE || 'env'
        const svc = new EncryptionService(mode)
        const raw = args.file
          ? readFileSync(args.file as string, 'utf8')
          : (args.json as string)
        const obj = JSON.parse(raw)
        const aad = parseAad(args.aad as string)
        const blob = await svc.encryptDict(obj, aad || {})
        console.log(blob)
      },
    )
    .command(
      'decrypt-json',
      'Decrypt a base64 blob and print JSON',
      (y) =>
        y
          .option('blob', {
            type: 'string',
            demandOption: true,
            describe: 'Base64-encoded blob',
          })
          .option('aad', {
            type: 'string',
            demandOption: true,
            describe: 'AAD JSON used on encrypt',
          })
          .option('mode', { type: 'string', choices: ['env', 'kms'] as const }),
      async (args) => {
        const mode =
          (args.mode as string | undefined) || process.env.ENC_MODE || 'env'
        const svc = new EncryptionService(mode)
        const aad = parseAad(args.aad as string) || {}
        const obj = await svc.decryptToDict(args.blob as string, aad)
        console.log(JSON.stringify(obj, null, 2))
      },
    )
    .demandCommand(1)
    .help()
    .strict()
    .parseSync()

  void argv
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
