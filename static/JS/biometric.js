// IndexedDB wrapper for secure biometric storage
const BiometricStorage = {
  dbName: 'PassAppBiometrics',
  storeName: 'credentials',
  
  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName, { keyPath: 'vaultName' });
        }
      };
    });
  },
  
  async set(vaultName, data) {
    const db = await this.init();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([this.storeName], 'readwrite');
      const request = tx.objectStore(this.storeName).put({ vaultName, ...data });
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  },
  
  async get(vaultName) {
    const db = await this.init();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([this.storeName], 'readonly');
      const request = tx.objectStore(this.storeName).get(vaultName);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  },
  
  async delete(vaultName) {
    const db = await this.init();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([this.storeName], 'readwrite');
      const request = tx.objectStore(this.storeName).delete(vaultName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  },
  
  async has(vaultName) {
    const data = await this.get(vaultName);
    return data !== undefined;
  }
};

/* After unlocking of vault and once user consents, call this method to set encrypted biometric key with DB pass */
async function enableBiometricForVault(vaultName, kdbxPassword) {
  try {
    // Create WebAuthn credential (triggers Face ID/Touch ID)
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: challenge,
        rp: {
          name: "PassApp",
          id: window.location.hostname  // your site name, for future ref.
        },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: vaultName,
          displayName: vaultName
        },
        pubKeyCredParams: [
          { alg: -7, type: "public-key" } // ES256 algorithm
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform", // On machine, not usb
          userVerification: "required" // biometric
        },
        timeout: 60000
      }
    });
    
    // Biometric prompts at this point
    console.log("Biometric registered!", credential.id);
    
    // Encrypt password with random key
    const encryptionKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedPassword = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      encryptionKey,
      new TextEncoder().encode(kdbxPassword)
    );
    
    // Export encryption key as raw bytes
    const keyData = await crypto.subtle.exportKey("raw", encryptionKey);
    
    // Store in IndexedDB
    await BiometricStorage.set(vaultName, {
      credentialId: arrayBufferToBase64(credential.rawId),
      encryptedPassword: arrayBufferToBase64(encryptedPassword),
      encryptionKey: arrayBufferToBase64(keyData),
      iv: arrayBufferToBase64(iv)
    });
    
    await fancyAlert("Face ID enabled for this vault!");
  } catch (error) {
    console.error("Biometric registration failed:", error);
    await fancyAlert("Biometric registration failed!");
    if (error.name === "NotAllowedError") {
      await fancyAlert("Face ID cancelled or not available");
    }
  }
}

async function unlockVaultWithBiometric(vaultName) {
  try {
    // Get stored data from IndexedDB
    const stored = await BiometricStorage.get(vaultName);
    if (!stored) {
      throw new Error("No biometric data for this vault");
    }

    const credentialId = base64ToArrayBuffer(stored.credentialId);

    // Authenticate with Biometric. Could be Face ID/Touch ID
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: challenge,
        rpId: window.location.hostname,
        allowCredentials: [{
          id: credentialId,
          type: "public-key"
        }],
        userVerification: "required", // Triggers biometric prompt
        timeout: 60000
      }
    });

    console.log("Biometric authenticated!");

    // Decrypt password
    const encryptionKey = await crypto.subtle.importKey(
      "raw",
      base64ToArrayBuffer(stored.encryptionKey),
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    
    const decryptedPasswordBuffer = await crypto.subtle.decrypt(
      { 
        name: "AES-GCM", 
        iv: base64ToArrayBuffer(stored.iv)
      },
      encryptionKey,
      base64ToArrayBuffer(stored.encryptedPassword)
    );

    const kdbxPassword = new TextDecoder().decode(decryptedPasswordBuffer);
    return kdbxPassword;

  } catch (error) {
    console.error("Biometric unlock failed:", error);
    await fancyAlert("Biometric unlock failed!");
    if (error.name === "NotAllowedError") {
      await fancyAlert("Face ID cancelled");
    }
    throw error; // Implement your own try/catch in usage of this method to handle failures
  }
}

function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
}

// Check if biometrics has previously been saved for the given vault name
async function isBiometricSavedForVault(vaultName) {
  return await BiometricStorage.has(vaultName);
}

async function isBiometricAvailable() {
  return window.PublicKeyCredential && 
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}