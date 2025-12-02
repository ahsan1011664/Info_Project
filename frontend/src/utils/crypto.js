/**
 * Cryptographic utilities using Web Crypto API
 * Handles key generation, encryption, and key management
 */

/**
 * Generate RSA-2048 key pair for digital signatures (long-term identity key)
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export const generateRSAKeyPair = async () => {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        // Use RSASSA for signatures (identity key)
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: 'SHA-256'
      },
      true, // extractable (needed to export and store)
      ['sign', 'verify']
    );

    console.log('✅ RSA-2048 key pair generated');
    return keyPair;
  } catch (error) {
    console.error('❌ Error generating RSA key pair:', error);
    throw error;
  }
};

/**
 * Generate ECC P-256 key pair
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export const generateECCKeyPair = async () => {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true, // extractable
      ['deriveKey', 'deriveBits']
    );

    console.log('✅ ECC P-256 key pair generated');
    return keyPair;
  } catch (error) {
    console.error('❌ Error generating ECC key pair:', error);
    throw error;
  }
};

/**
 * Export public key to SPKI format (for sending to server)
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>} Base64 encoded SPKI
 */
export const exportPublicKeySPKI = async (publicKey) => {
  try {
    const exported = await crypto.subtle.exportKey('spki', publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
    return base64;
  } catch (error) {
    console.error('❌ Error exporting public key:', error);
    throw error;
  }
};

/**
 * Export private key to JWK format (for storing in IndexedDB)
 * @param {CryptoKey} privateKey
 * @returns {Promise<Object>} JWK object
 */
export const exportPrivateKeyJWK = async (privateKey) => {
  try {
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    return jwk;
  } catch (error) {
    console.error('❌ Error exporting private key:', error);
    throw error;
  }
};

/**
 * Import public key from SPKI format
 * @param {string} base64SPKI - Base64 encoded SPKI
 * @param {string} algorithm - 'RSA-OAEP' or 'ECDH'
 * @returns {Promise<CryptoKey>}
 */
export const importPublicKeySPKI = async (base64SPKI, algorithm = 'RSA-OAEP') => {
  try {
    const binaryString = atob(base64SPKI);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    const keyData = { name: algorithm };

    let usages = [];

    if (algorithm === 'RSA-OAEP' || algorithm === 'RSASSA-PKCS1-v1_5') {
      keyData.hash = 'SHA-256';
    }

    if (algorithm === 'ECDH') {
      // ECDH public keys must have no key usages
      keyData.namedCurve = 'P-256';
      usages = [];
    } else if (algorithm === 'RSA-OAEP') {
      usages = ['encrypt'];
    } else if (algorithm === 'RSASSA-PKCS1-v1_5') {
      usages = ['verify'];
    }

    const publicKey = await crypto.subtle.importKey('spki', bytes, keyData, false, usages);

    return publicKey;
  } catch (error) {
    console.error('❌ Error importing public key:', error);
    throw error;
  }
};

/**
 * Import private key from JWK format
 * @param {Object} jwk - JWK object
 * @param {string} algorithm - 'RSA-OAEP' or 'ECDH'
 * @returns {Promise<CryptoKey>}
 */
export const importPrivateKeyJWK = async (jwk, algorithm = 'RSA-OAEP') => {
  try {
    const keyData = {
      name: algorithm,
      hash:
        algorithm === 'RSA-OAEP' || algorithm === 'RSASSA-PKCS1-v1_5'
          ? 'SHA-256'
          : undefined
    };

    if (algorithm === 'ECDH') {
      keyData.namedCurve = 'P-256';
    }

    let usages;
    if (algorithm === 'RSA-OAEP') {
      usages = ['decrypt'];
    } else if (algorithm === 'RSASSA-PKCS1-v1_5') {
      usages = ['sign'];
    } else {
      usages = ['deriveKey', 'deriveBits'];
    }

    const privateKey = await crypto.subtle.importKey('jwk', jwk, keyData, true, usages);

    return privateKey;
  } catch (error) {
    console.error('❌ Error importing private key:', error);
    throw error;
  }
};

/**
 * Generate and store key pair for a user
 * @param {string} username
 * @param {string} algorithm - 'RSA-OAEP' or 'ECDH' (default: 'RSA-OAEP')
 * @returns {Promise<{publicKeySPKI: string, algorithm: string}>}
 */
export const generateAndStoreKeyPair = async (username, algorithm = 'RSA-OAEP') => {
  try {
    // Generate key pair
    let keyPair;
    if (algorithm === 'RSA-OAEP' || algorithm === 'RSASSA-PKCS1-v1_5') {
      keyPair = await generateRSAKeyPair();
    } else if (algorithm === 'ECDH') {
      keyPair = await generateECCKeyPair();
    } else {
      throw new Error('Unsupported algorithm. Use RSA-OAEP or ECDH');
    }

    // Export public key (to send to server)
    const publicKeySPKI = await exportPublicKeySPKI(keyPair.publicKey);

    // Export private key (to store locally)
    const privateKeyJWK = await exportPrivateKeyJWK(keyPair.privateKey);

    // Store private key in IndexedDB
    const { storePrivateKey } = await import('./indexedDB');
    await storePrivateKey(username, privateKeyJWK);

    console.log(`✅ Key pair generated and stored for user: ${username}`);

    return {
      publicKeySPKI,
      algorithm
    };
  } catch (error) {
    console.error('❌ Error in generateAndStoreKeyPair:', error);
    throw error;
  }
};

