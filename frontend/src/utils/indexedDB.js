/**
 * IndexedDB utility for storing private keys securely
 * Database: SecureKeyStore
 * Object Store: privateKeys
 */

const DB_NAME = 'SecureKeyStore';
const DB_VERSION = 1;
const STORE_NAME = 'privateKeys';

/**
 * Open or create IndexedDB database
 */
export const openDB = () => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      reject(new Error('Failed to open IndexedDB'));
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      
      // Create object store if it doesn't exist
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const objectStore = db.createObjectStore(STORE_NAME, { 
          keyPath: 'username' 
        });
        objectStore.createIndex('username', 'username', { unique: true });
        console.log('✅ IndexedDB object store created');
      }
    };
  });
};

/**
 * Store private key in IndexedDB
 * @param {string} username - User's username
 * @param {Object} privateKeyJWK - Private key in JWK format
 */
export const storePrivateKey = async (username, privateKeyJWK) => {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const keyData = {
      username: username,
      privateKey: privateKeyJWK,
      createdAt: new Date().toISOString()
    };

    await new Promise((resolve, reject) => {
      const request = store.put(keyData);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to store private key'));
    });

    console.log(`✅ Private key stored for user: ${username}`);
    return true;
  } catch (error) {
    console.error('❌ Error storing private key:', error);
    throw error;
  }
};

/**
 * Retrieve private key from IndexedDB
 * @param {string} username - User's username
 * @returns {Object} Private key in JWK format
 */
export const getPrivateKey = async (username) => {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);

    return new Promise((resolve, reject) => {
      const request = store.get(username);
      request.onsuccess = () => {
        if (request.result) {
          resolve(request.result.privateKey);
        } else {
          reject(new Error('Private key not found'));
        }
      };
      request.onerror = () => {
        reject(new Error('Failed to retrieve private key'));
      };
    });
  } catch (error) {
    console.error('❌ Error retrieving private key:', error);
    throw error;
  }
};

/**
 * Check if private key exists for user
 * @param {string} username - User's username
 * @returns {boolean}
 */
export const hasPrivateKey = async (username) => {
  try {
    await getPrivateKey(username);
    return true;
  } catch {
    return false;
  }
};

/**
 * Delete private key from IndexedDB (e.g., on logout)
 * @param {string} username - User's username
 */
export const deletePrivateKey = async (username) => {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    await new Promise((resolve, reject) => {
      const request = store.delete(username);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to delete private key'));
    });

    console.log(`✅ Private key deleted for user: ${username}`);
    return true;
  } catch (error) {
    console.error('❌ Error deleting private key:', error);
    throw error;
  }
};

