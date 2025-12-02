/**
 * Custom Secure Key Exchange Protocol (KX-V1)
 *
 * Uses:
 * - Ephemeral ECDH (P-256) for shared secret
 * - Long-term RSA-2048 (RSASSA-PKCS1-v1_5) keys for digital signatures
 * - HKDF-SHA-256 to derive AES-256-GCM session key
 * - Encrypted key-confirmation messages
 *
 * This file only contains pure crypto + message-building helpers.
 * Networking (sending messages between users) should be implemented separately.
 */

import { exportPublicKeySPKI, importPublicKeySPKI, importPrivateKeyJWK } from './crypto';
import { getPrivateKey } from './indexedDB';

// Utility helpers
const utf8Encode = (str) => new TextEncoder().encode(str);
const utf8Decode = (buf) => new TextDecoder().decode(buf);

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

// Deterministic JSON serialization (simple manual ordering)
const serializeBody = (body) => {
  // For simplicity, rely on JSON.stringify with stable key usage in our own objects.
  // Ensure all callers build objects with the same field order.
  return JSON.stringify(body);
};

// HKDF wrapper to derive an AES-GCM key from shared secret
const deriveAesKeyFromSecret = async (sharedSecretBytes, saltBytes, infoStr) => {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    sharedSecretBytes,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  const infoBytes = utf8Encode(infoStr);

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBytes,
      info: infoBytes
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return aesKey;
};

// SHA-256 hash helper, returns base64 string
const sha256Base64 = async (bytes) => {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return toBase64(digest);
};

// Generate ephemeral ECDH key pair (P-256)
const generateEphemeralECDHKeyPair = async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveBits']
  );
  return keyPair;
};

// Derive shared secret (raw bits) using ECDH
const deriveSharedSecret = async (myPrivateKey, theirPublicKey) => {
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: theirPublicKey
    },
    myPrivateKey,
    256 // 256 bits of shared secret
  );
  return new Uint8Array(bits);
};

// Load long-term signing private key (RSASSA) for a user from IndexedDB
const loadSigningPrivateKey = async (username) => {
  const jwk = await getPrivateKey(username);
  return importPrivateKeyJWK(jwk, 'RSASSA-PKCS1-v1_5');
};

// Load peer's long-term signing public key (RSASSA) from SPKI base64
const loadSigningPublicKey = async (base64SPKI) => {
  return importPublicKeySPKI(base64SPKI, 'RSASSA-PKCS1-v1_5');
};

// Sign serialized body with RSASSA private key, output base64 signature
const signBody = async (privateKey, bodyObj) => {
  const serialized = serializeBody(bodyObj);
  const data = utf8Encode(serialized);
  const sig = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    data
  );
  return toBase64(sig);
};

// Verify signature over body with RSASSA public key
const verifyBodySignature = async (publicKey, bodyObj, signatureB64) => {
  const serialized = serializeBody(bodyObj);
  const data = utf8Encode(serialized);
  const sigBytes = fromBase64(signatureB64);
  const ok = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    publicKey,
    sigBytes,
    data
  );
  return ok;
};

// Create KEY_INIT message as initiator (A)
export const createKeyInit = async (fromUsername, toUsername) => {
  const sessionId = toBase64(randomBytes(16)); // 128-bit
  const nonceA = toBase64(randomBytes(12)); // 96-bit

  const eph = await generateEphemeralECDHKeyPair();
  const ephPubSPKI = await exportPublicKeySPKI(eph.publicKey);

  const body = {
    type: 'KEY_INIT',
    protocolVersion: 'KX-V1',
    sessionId,
    from: fromUsername,
    to: toUsername,
    timestamp: Date.now(),
    seq: 1,
    nonceA,
    A_ephemeralPub: ephPubSPKI
  };

  const signingPriv = await loadSigningPrivateKey(fromUsername);
  const signature = await signBody(signingPriv, body);

  return {
    body,
    signature,
    // Keep ephemeral private key and nonceA so caller can continue protocol
    context: {
      sessionId,
      nonceA,
      A_ephemeralPriv: eph.privateKey,
      A_ephemeralPub: eph.publicKey
    }
  };
};

// Process incoming KEY_INIT on responder side (B) and create KEY_RESP
export const processKeyInitAndCreateResp = async (
  keyInitBody,
  keyInitSignature,
  initiatorPublicKeySPKI,
  responderUsername
) => {
  // 1) Verify initiator's signature
  const initiatorPub = await loadSigningPublicKey(initiatorPublicKeySPKI);
  const valid = await verifyBodySignature(initiatorPub, keyInitBody, keyInitSignature);
  if (!valid) {
    throw new Error('Invalid signature on KEY_INIT');
  }

  // 2) Generate responder ephemeral key and derive shared secret
  const ephB = await generateEphemeralECDHKeyPair();
  const ephBPubSPKI = await exportPublicKeySPKI(ephB.publicKey);

  const A_ephemeralPubKey = await importPublicKeySPKI(
    keyInitBody.A_ephemeralPub,
    'ECDH'
  );

  const sharedSecret = await deriveSharedSecret(ephB.privateKey, A_ephemeralPubKey);

  // 3) Derive AES session key using HKDF
  const nonceABytes = fromBase64(keyInitBody.nonceA);
  const nonceBBytes = randomBytes(12);
  const nonceB = toBase64(nonceBBytes);

  const salt = new Uint8Array(nonceABytes.length + nonceBBytes.length);
  salt.set(nonceABytes, 0);
  salt.set(nonceBBytes, nonceABytes.length);

  // Use a stable "info" string so both sides derive the same key:
  // always (sessionId | initiator | responder) where initiator = keyInitBody.from, responder = keyInitBody.to
  const initiatorId = keyInitBody.from;
  const responderId = keyInitBody.to;
  const infoStr = `KX-V1|${keyInitBody.sessionId}|${initiatorId}|${responderId}`;
  const aesKey = await deriveAesKeyFromSecret(sharedSecret, salt, infoStr);

  // 4) Build KEY_RESP
  const body = {
    type: 'KEY_RESP',
    protocolVersion: 'KX-V1',
    sessionId: keyInitBody.sessionId,
    from: responderUsername,
    to: keyInitBody.from,
    timestamp: Date.now(),
    seq: 1,
    nonceB,
    B_ephemeralPub: ephBPubSPKI
  };

  const signingPriv = await loadSigningPrivateKey(responderUsername);
  const signature = await signBody(signingPriv, body);

  // Transcript hash for later confirmation
  const initBytes = utf8Encode(serializeBody(keyInitBody));
  const respBytes = utf8Encode(serializeBody(body));
  const transcriptConcat = new Uint8Array(initBytes.length + respBytes.length);
  transcriptConcat.set(initBytes, 0);
  transcriptConcat.set(respBytes, initBytes.length);
  const transcriptHash = await sha256Base64(transcriptConcat);

  return {
    body,
    signature,
    sessionContext: {
      sessionId: keyInitBody.sessionId,
      aesKey,
      nonceA: keyInitBody.nonceA,
      nonceB,
      transcriptHash
    }
  };
};

// Process KEY_RESP on initiator side and derive same session key
export const processKeyRespAndDeriveKey = async (
  keyRespBody,
  keyRespSignature,
  responderPublicKeySPKI,
  keyInitBody,
  initContext
) => {
  const responderPub = await loadSigningPublicKey(responderPublicKeySPKI);
  const valid = await verifyBodySignature(responderPub, keyRespBody, keyRespSignature);
  if (!valid) {
    throw new Error('Invalid signature on KEY_RESP');
  }

  if (keyRespBody.sessionId !== initContext.sessionId || keyRespBody.sessionId !== keyInitBody.sessionId) {
    throw new Error('Session ID mismatch in KEY_RESP');
  }

  const B_ephemeralPubKey = await importPublicKeySPKI(
    keyRespBody.B_ephemeralPub,
    'ECDH'
  );

  const sharedSecret = await deriveSharedSecret(
    initContext.A_ephemeralPriv,
    B_ephemeralPubKey
  );

  const nonceABytes = fromBase64(initContext.nonceA);
  const nonceBBytes = fromBase64(keyRespBody.nonceB);

  const salt = new Uint8Array(nonceABytes.length + nonceBBytes.length);
  salt.set(nonceABytes, 0);
  salt.set(nonceBBytes, nonceABytes.length);

  // Must match responder's infoStr exactly: (sessionId | initiator | responder)
  const initiatorId = keyInitBody.from;
  const responderId = keyInitBody.to;
  const infoStr = `KX-V1|${keyInitBody.sessionId}|${initiatorId}|${responderId}`;
  const aesKey = await deriveAesKeyFromSecret(sharedSecret, salt, infoStr);

  // Compute transcript hash identically to responder
  const initBytes = utf8Encode(serializeBody(keyInitBody));
  const respBytes = utf8Encode(serializeBody(keyRespBody));
  const concat = new Uint8Array(initBytes.length + respBytes.length);
  concat.set(initBytes, 0);
  concat.set(respBytes, initBytes.length);
  const transcriptHash = await sha256Base64(concat);

  return {
    aesKey,
    sessionId: keyRespBody.sessionId,
    nonceA: initContext.nonceA,
    nonceB: keyRespBody.nonceB,
    transcriptHash
  };
};

// Create encrypted KEY_CONFIRM (used by both sides)
export const createKeyConfirm = async (type, sessionId, from, to, aesKey, transcriptHash) => {
  const plaintextObj = {
    type,
    sessionId,
    from,
    to,
    timestamp: Date.now(),
    seq: 2,
    transcriptHash
  };

  const plaintextBytes = utf8Encode(serializeBody(plaintextObj));
  const iv = randomBytes(12);
  const additionalData = utf8Encode(`${sessionId}|${type}`);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData
    },
    aesKey,
    plaintextBytes
  );

  return {
    sessionId,
    from,
    to,
    type,
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext)
  };
};

// Decrypt and verify KEY_CONFIRM
export const decryptAndVerifyKeyConfirm = async (
  confirmMsg,
  aesKey,
  expectedTranscriptHash
) => {
  const iv = fromBase64(confirmMsg.iv);
  const ciphertext = fromBase64(confirmMsg.ciphertext);
  const additionalData = utf8Encode(`${confirmMsg.sessionId}|${confirmMsg.type}`);

  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData
    },
    aesKey,
    ciphertext
  );

  const obj = JSON.parse(utf8Decode(plaintext));

  if (obj.transcriptHash !== expectedTranscriptHash) {
    throw new Error('Transcript hash mismatch in KEY_CONFIRM');
  }

  return obj;
};


