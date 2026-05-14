import crypto from "crypto";

/**
 * Decrypts a payload encrypted by addon/Crypto.gs.
 *
 * Scheme: HMAC-SHA256-CTR + HMAC-SHA256 authentication tag.
 * Wire format (base64-decoded): nonce[16] || ciphertext[n] || mac[32]
 *
 * Throws on invalid key, truncated payload, or MAC mismatch.
 */
export function decryptPayload(enc: string, hexKey: string): string {
  const key = Buffer.from(hexKey, "hex");
  if (key.length !== 32) throw new Error("INVALID_KEY_LENGTH");

  const encKey = crypto.createHmac("sha256", key).update("encryption").digest();
  const macKey = crypto.createHmac("sha256", key).update("authentication").digest();

  const combined = Buffer.from(enc, "base64");
  if (combined.length < 16 + 32) throw new Error("PAYLOAD_TOO_SHORT");

  const nonce      = combined.subarray(0, 16);
  const mac        = combined.subarray(combined.length - 32);
  const ciphertext = combined.subarray(16, combined.length - 32);

  // Verify MAC before decrypting (timing-safe, prevents padding oracle attacks)
  const expected = crypto
    .createHmac("sha256", macKey)
    .update(Buffer.concat([nonce, ciphertext]))
    .digest();
  if (!crypto.timingSafeEqual(mac, expected)) throw new Error("INVALID_MAC");

  // HMAC-CTR decryption — mirrors Crypto.gs hmacCTR()
  const plaintext = Buffer.alloc(ciphertext.length);
  const blockSize = 32;
  let block = Buffer.alloc(0);

  for (let i = 0; i < ciphertext.length; i++) {
    if (i % blockSize === 0) {
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(Math.floor(i / blockSize), 0);
      block = crypto
        .createHmac("sha256", encKey)
        .update(Buffer.concat([nonce, counter]))
        .digest();
    }
    plaintext[i] = ciphertext[i] ^ block[i % blockSize];
  }

  return plaintext.toString("utf8");
}
