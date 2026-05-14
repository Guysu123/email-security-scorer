import crypto from "crypto";

/**
 * Encrypts a JSON string using HMAC-SHA256-CTR + HMAC-SHA256 MAC.
 * Mirrors addon/Crypto.gs encryptPayload() and is compatible with
 * backend/lib/encryption.ts decryptPayload().
 *
 * Wire format (base64-encoded): nonce[16] || ciphertext[n] || mac[32]
 * Key format: 64 hex characters (32 bytes).
 */
export function encryptPayload(jsonString: string, hexKey: string): string {
  const key    = Buffer.from(hexKey, "hex");
  const encKey = crypto.createHmac("sha256", key).update("encryption").digest();
  const macKey = crypto.createHmac("sha256", key).update("authentication").digest();
  const nonce  = crypto.randomBytes(16);

  const plaintext  = Buffer.from(jsonString, "utf8");
  const ciphertext = hmacCTR(encKey, nonce, plaintext);
  const mac        = crypto.createHmac("sha256", macKey)
    .update(Buffer.concat([nonce, ciphertext]))
    .digest();

  return Buffer.concat([nonce, ciphertext, mac]).toString("base64");
}

function hmacCTR(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
  const blockSize = 32;
  const result    = Buffer.alloc(plaintext.length);
  let   block     = Buffer.alloc(0);

  for (let i = 0; i < plaintext.length; i++) {
    if (i % blockSize === 0) {
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(Math.floor(i / blockSize), 0);
      block = crypto.createHmac("sha256", key)
        .update(Buffer.concat([nonce, counter]))
        .digest();
    }
    result[i] = plaintext[i] ^ block[i % blockSize];
  }
  return result;
}
