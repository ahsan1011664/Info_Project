/**
 * AES-256-GCM message encryption/decryption using Web Crypto
 * Used for end-to-end encrypted chat messages.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

const toBase64 = (bytes) => {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
};

const fromBase64 = (b64) => {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    arr[i] = bin.charCodeAt(i);
  }
  return arr;
};

const randomBytes = (len) => {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return arr;
};

/**
 * Encrypt a chat message with AES-256-GCM using an existing CryptoKey (K_enc)
 * @param {CryptoKey} aesKey
 * @param {string} sessionId
 * @param {string} from
 * @param {string} to
 * @param {number} msgSeq
 * @param {string} content
 */
export const encryptMessage = async (aesKey, sessionId, from, to, msgSeq, content) => {
  const timestamp = Date.now();

  const plaintextObj = {
    sessionId,
    from,
    to,
    msgSeq,
    timestamp,
    content
  };

  const plaintextBytes = enc.encode(JSON.stringify(plaintextObj));

  const iv = randomBytes(12); // 96-bit IV
  const aad = enc.encode(`${sessionId}|${from}|${to}|${msgSeq}`);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad
    },
    aesKey,
    plaintextBytes
  );

  return {
    ciphertext: toBase64(ciphertext),
    iv: toBase64(iv),
    timestamp,
    msgSeq
  };
};

/**
 * Decrypt an encrypted message using AES-256-GCM and return plaintext content
 * @param {CryptoKey} aesKey
 * @param {Object} message - { from, to, sessionId, ciphertext, iv, msgSeq, timestamp }
 */
export const decryptMessage = async (aesKey, message) => {
  const { from, to, sessionId, ciphertext, iv, msgSeq, timestamp } = message;

  const ivBytes = fromBase64(iv);
  const cipherBytes = fromBase64(ciphertext);
  const aad = enc.encode(`${sessionId}|${from}|${to}|${msgSeq}`);

  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes,
      additionalData: aad
    },
    aesKey,
    cipherBytes
  );

  const obj = JSON.parse(dec.decode(plaintext));

  return {
    from,
    to,
    sessionId,
    msgSeq,
    timestamp: obj.timestamp || timestamp,
    content: obj.content
  };
};


