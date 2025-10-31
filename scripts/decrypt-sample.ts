import { EncryptionService } from '../src/services/encryptionService.js'

// Hardcoded inputs from your message
const APP_DATA_KEY = 'IsIf0vDoJsXlJutJNY4SHEZBlY1En5cE1eo42SXjXUY=' // base64 32 bytes
const ENCRYPTED_ENV =
  'djEGZW52LXYxJ6ojoieTAGqbmBMtmjS2lOpq2V0x/pHrFC69KPx/9+z3RYkBxjDlSRkXx0Z7Txcu5/KVIvPsc+M='
const AAD_JSON = {
  user_email: 'oleksandr.savchuk@cprime.com',
  server_name: 'mcp-server-node',
  app_name: 'cprime',
  purpose: 'user-config',
}

async function main() {
  // Ensure env mode key is present
  process.env.APP_DATA_KEY = APP_DATA_KEY
  if (!process.env.APP_DATA_KEY_ID) process.env.APP_DATA_KEY_ID = 'env-v1'

  const svc = new EncryptionService('env')
  const plaintext = await svc.decryptText(ENCRYPTED_ENV, AAD_JSON)

  // Pretty print if plaintext is JSON
  try {
    const asObj = JSON.parse(plaintext)
    console.log(JSON.stringify(asObj, null, 2))
  } catch {
    console.log(plaintext)
  }
}

main().catch((err) => {
  console.error('Decryption failed:', err)
  process.exit(1)
})
