/**
 * Payload encryption for the /api/analyze request.
 *
 * Scheme: HMAC-SHA256-CTR + HMAC-SHA256 authentication tag.
 * No external libraries — built entirely on Apps Script's Utilities class.
 *
 * Wire format (base64-encoded):
 *   nonce[16] || ciphertext[n] || mac[32]
 *
 * Key format: 64 hex characters (32 bytes / 256 bits).
 * Three subkeys are derived via HMAC so the master key is never used directly:
 *   encKey  = HMAC(masterKey, "encryption")
 *   macKey  = HMAC(masterKey, "authentication")
 *   nonceKey = HMAC(masterKey, "nonce")
 *
 * Nonce derivation (SIV — Synthetic IV):
 *   nonce = HMAC(nonceKey, plaintext)[0:16]
 *
 * This eliminates the need for a CSPRNG. Apps Script exposes no native
 * cryptographically-secure random source (Math.random() is xorshift128+
 * seeded by the clock and is not suitable for nonce generation).
 *
 * Security property: nonce reuse occurs only if the exact same plaintext is
 * encrypted twice with the same key, which reveals only that the same message
 * was sent twice — nothing about the content. This is provably secure under
 * the same PRF assumption the MAC already depends on.
 *
 * Compatible with backend/lib/encryption.ts (Node.js crypto module).
 */

function encryptPayload(jsonString, hexKey) {
  var keyBytes  = hexDecode(hexKey);
  var encKey    = hmacSha256(keyBytes, strToBytes("encryption"));
  var macKey    = hmacSha256(keyBytes, strToBytes("authentication"));
  var nonceKey  = hmacSha256(keyBytes, strToBytes("nonce"));

  var plaintext = strToBytes(jsonString);

  // Derive nonce deterministically from the plaintext — no PRNG required.
  var nonce = hmacSha256(nonceKey, plaintext).slice(0, 16);

  var ciphertext = hmacCTR(encKey, nonce, plaintext);
  var mac        = hmacSha256(macKey, nonce.concat(ciphertext));

  return Utilities.base64Encode(toSigned(nonce.concat(ciphertext).concat(mac)));
}

// ── HMAC-CTR stream cipher ────────────────────────────────────────────────────

function hmacCTR(key, nonce, plaintext) {
  var result     = [];
  var blockSize  = 32; // SHA-256 output is 32 bytes
  var keystream  = [];

  for (var i = 0; i < plaintext.length; i++) {
    if (i % blockSize === 0) {
      var n       = Math.floor(i / blockSize);
      var counter = [(n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF];
      keystream   = hmacSha256(key, nonce.concat(counter));
    }
    result.push((plaintext[i] ^ keystream[i % blockSize]) & 0xFF);
  }
  return result;
}

// ── Byte helpers ──────────────────────────────────────────────────────────────

function hmacSha256(key, data) {
  // Utilities expects signed bytes (-128..127); returns signed bytes — normalise both ways.
  return toUnsigned(
    Utilities.computeHmacSha256Signature(toSigned(data), toSigned(key))
  );
}

function strToBytes(str) {
  return toUnsigned(Utilities.newBlob(str, "text/plain").getBytes());
}

function hexDecode(hex) {
  var bytes = [];
  for (var i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

// Apps Script byte arrays are signed (-128..127). These conversions let the
// rest of the code work with unsigned integers (0..255).
function toUnsigned(arr) { return arr.map(function(b) { return b & 0xFF; }); }
function toSigned(arr)   { return arr.map(function(b) { return b > 127 ? b - 256 : b; }); }
