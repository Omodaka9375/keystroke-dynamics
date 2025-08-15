/**
 * Keystroke Dynamics Authentication System
 * Passwordless Web Authentication
 */

// Configuration Constants
const CONFIG = Object.freeze({
    DATABASE: {
        NAME: 'keystroke_dynamics_db',
        VERSION: 1,
        STORES: {
            SIGNATURES: 'dynamics_signatures',
            MASTER: 'master_keys',
            CREDENTIALS: 'user_credentials'
        }
    },
    
    BIOMETRICS: {
        MIN_SAMPLES: 3,
        MAX_SAMPLES: 10,
        DEFAULT_THRESHOLD: 0.70, // Changed to match your default
        THRESHOLDS: {
            LOW: 0.60,
            MEDIUM: 0.70,
            HIGH: 0.80,
            MAX: 0.90
        }
    },
    
    CRYPTO: {
        PBKDF2_ITERATIONS: 100000,
        AES_KEY_LENGTH: 256,
        SALT_LENGTH: 16,
        IV_LENGTH: 12
    },
    
    TIMING: {
        SAMPLE_TIMEOUT: 30000, // 30 seconds max per sample
        MIN_KEYSTROKE_INTERVAL: 50, // 50ms minimum between keystrokes
        MAX_KEYSTROKE_INTERVAL: 5000 // 5s maximum between keystrokes
    }
});

// Allowed characters for keystroke capture
const ALLOWED_CHARS = Object.freeze([
    /* --------------------------------------------------------------------
       Letters – lower & upper case
    -------------------------------------------------------------------- */
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
  
    /* --------------------------------------------------------------------
       Digits
    -------------------------------------------------------------------- */
    '0','1','2','3','4','5','6','7','8','9',
  
    /* --------------------------------------------------------------------
       Punctuation & symbols (the ones that have a key on the keyboard)
    -------------------------------------------------------------------- */
    '`', '~', '!', '@', '#', '$', '%', '^', '&', '*',
    '(', ')', '-', '_', '=', '+', '[', '{', ']', '}',
    '\\', '|', ';', ':', '\'', '"', ',', '<', '.', '>',
    '/', '?',
  
    /* --------------------------------------------------------------------
       Space, Tab, Enter
    -------------------------------------------------------------------- */
    'space', 'tab', 'enter',
  
    /* --------------------------------------------------------------------
       Arrow keys & navigation
    -------------------------------------------------------------------- */
    'up', 'down', 'left', 'right',
    'home', 'end', 'pageUp', 'pageDown',
  
    /* --------------------------------------------------------------------
       Editing keys
    -------------------------------------------------------------------- */
    'backspace', 'delete', 'insert',
  
    /* --------------------------------------------------------------------
       Modifier keys
    -------------------------------------------------------------------- */
    'shift', 'control', 'ctrl', 'alt', 'meta', 'cmd',
    'capsLock', 'numLock', 'scrollLock',
  
    /* --------------------------------------------------------------------
       Function keys (F1–F12)
    -------------------------------------------------------------------- */
    'f1','f2','f3','f4','f5','f6','f7','f8','f9','f10','f11','f12',
  ]);

// Custom Error Classes
class DynamicsError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'DynamicsError';
        this.code = code;
    }
}

class CryptoError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'CryptoError';
        this.code = code;
    }
}

class DatabaseError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'DatabaseError';
        this.code = code;
    }
}

// Utility Functions - FIXED
const Utils = {
    // Performance timing
    getHighResTime() {
        return performance.now ? performance.now() : Date.now();
    },

    // Buffer encoding
    buffToBase64(buffer) {
        return btoa(String.fromCharCode.apply(null, buffer));
    },

    base64ToBuff(base64) {
        return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    },

    // FIXED: Single normalizeKey method with comprehensive mapping
    normalizeKey(key) {
        if (!key || typeof key !== 'string') return '';
        
        // Handle special cases
        const keyMap = {
            '.': 'period',
            ' ': 'space',
            'Enter': 'enter',
            'Backspace': 'backspace',
            'Tab': 'tab',
            'Shift': 'shift',
            'Control': 'ctrl',
            'Alt': 'alt',
            'Meta': 'meta'
        };
        
        return keyMap[key] || key.toLowerCase();
    },

    // FIXED: Use the single normalizeKey method
    isValidChar(char) {
        const normalized = this.normalizeKey(char);
        return ALLOWED_CHARS.includes(normalized);
    },

    // Mathematical operations
    calculateMedian(values) {
        if (!values.length) return 0;
        const sorted = [...values].sort((a, b) => a - b);
        const middle = Math.floor(sorted.length / 2);
        return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
    },

    dotProduct(a, b) {
        if (a.length !== b.length) throw new Error('Vector length mismatch');
        return a.reduce((sum, val, i) => sum + val * b[i], 0);
    },

    cosineSimilarity(a, b) {
        try {
            const dotProd = this.dotProduct(a, b);
            const magA = Math.sqrt(this.dotProduct(a, a));
            const magB = Math.sqrt(this.dotProduct(b, b));
            return (magA === 0 || magB === 0) ? 0 : dotProd / (magA * magB);
        } catch (error) {
            console.warn('Cosine similarity calculation failed:', error);
            return 0;
        }
    },

    // Cryptographic hash
    async hash256(data) {
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
};

// Cryptography Service
class CryptoService {
    static async #getPasswordKey(password) {
        const encoder = new TextEncoder();
        return crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
    }

    static async #deriveKey(passwordKey, salt, keyUsage) {
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt,
                iterations: CONFIG.CRYPTO.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-GCM', length: CONFIG.CRYPTO.AES_KEY_LENGTH },
            false,
            keyUsage
        );
    }

    static async encrypt(data, password) {
        try {
            const encoder = new TextEncoder();
            const salt = crypto.getRandomValues(new Uint8Array(CONFIG.CRYPTO.SALT_LENGTH));
            const iv = crypto.getRandomValues(new Uint8Array(CONFIG.CRYPTO.IV_LENGTH));

            const passwordKey = await this.#getPasswordKey(password);
            const aesKey = await this.#deriveKey(passwordKey, salt, ['encrypt']);

            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                aesKey,
                encoder.encode(data)
            );

            // Combine salt + iv + encrypted data
            const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            combined.set(salt, 0);
            combined.set(iv, salt.length);
            combined.set(new Uint8Array(encrypted), salt.length + iv.length);

            return Utils.buffToBase64(combined);
        } catch (error) {
            throw new CryptoError(`Encryption failed: ${error.message}`, 'ENCRYPT_FAILED');
        }
    }

    static async decrypt(encryptedData, password) {
        try {
            const combined = Utils.base64ToBuff(encryptedData);
            const salt = combined.slice(0, CONFIG.CRYPTO.SALT_LENGTH);
            const iv = combined.slice(CONFIG.CRYPTO.SALT_LENGTH, CONFIG.CRYPTO.SALT_LENGTH + CONFIG.CRYPTO.IV_LENGTH);
            const data = combined.slice(CONFIG.CRYPTO.SALT_LENGTH + CONFIG.CRYPTO.IV_LENGTH);

            const passwordKey = await this.#getPasswordKey(password);
            const aesKey = await this.#deriveKey(passwordKey, salt, ['decrypt']);

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                aesKey,
                data
            );

            return new TextDecoder().decode(decrypted);
        } catch (error) {
            throw new CryptoError(`Decryption failed: ${error.message}`, 'DECRYPT_FAILED');
        }
    }
}

// Database Service
class DynamicsDatabase {
    constructor() {
        this.dbName = CONFIG.DATABASE.NAME;
        this.version = CONFIG.DATABASE.VERSION;
        this.stores = CONFIG.DATABASE.STORES;
    }

    async #openDatabase() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);

            request.onerror = () => reject(new DatabaseError('Failed to open database', 'DB_OPEN_FAILED'));
            request.onsuccess = () => resolve(request.result);

            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create object stores
                Object.values(this.stores).forEach(storeName => {
                    if (!db.objectStoreNames.contains(storeName)) {
                        db.createObjectStore(storeName, { keyPath: 'id', autoIncrement: true });
                    }
                });
            };
        });
    }

    async save(storeName, data) {
        const db = await this.#openDatabase();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.add(data);

            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(new DatabaseError('Save failed', 'SAVE_FAILED'));
            transaction.oncomplete = () => db.close();
        });
    }

    async loadAll(storeName) {
        const db = await this.#openDatabase();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readonly');
            const store = transaction.objectStore(storeName);
            const request = store.getAll();

            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(new DatabaseError('Load failed', 'LOAD_FAILED'));
            transaction.oncomplete = () => db.close();
        });
    }

    async clear(storeName) {
        const db = await this.#openDatabase();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.clear();

            request.onsuccess = () => resolve(true);
            request.onerror = () => reject(new DatabaseError('Clear failed', 'CLEAR_FAILED'));
            transaction.oncomplete = () => db.close();
        });
    }
}

// FIXED: Feature Extractor with correct error types
class FeatureExtractor {
    static extract(keystrokes) {
        console.log('Extracting features from keystrokes:', keystrokes);
        
        if (!keystrokes || keystrokes.length === 0) {
            throw new DynamicsError('No keystroke data provided', 'NO_DATA'); // FIXED: DynamicsError
        }

        const events = this.#categorizeAndCleanEvents(keystrokes);
        this.#validateEvents(events);
        
        return this.#computeFeatures(events);
    }

    static #categorizeAndCleanEvents(keystrokes) {
        const downEvents = [];
        const upEvents = [];
        const seenKeys = new Map(); // Track key presses to match up/down

        // First pass: collect all events and match pairs
        for (const event of keystrokes) {
            if (event.type === 'keydown') {
                // Store the keydown event
                seenKeys.set(event.key, event);
                downEvents.push(event);
            } else if (event.type === 'keyup') {
                // Only add keyup if we have a matching keydown
                const matchingDown = seenKeys.get(event.key);
                if (matchingDown) {
                    upEvents.push(event);
                    seenKeys.delete(event.key); // Remove to handle multiple same keys
                }
            }
        }

        console.log(`Categorized events - Down: ${downEvents.length}, Up: ${upEvents.length}`);
        
        return { downEvents, upEvents };
    }

    static #validateEvents({ downEvents, upEvents }) {
        if (downEvents.length === 0) {
            throw new DynamicsError('No keydown events found', 'NO_KEYDOWN'); // FIXED
        }
        
        if (upEvents.length === 0) {
            throw new DynamicsError('No keyup events found', 'NO_KEYUP'); // FIXED
        }

        // Allow some tolerance in event count mismatch
        const tolerance = Math.min(2, Math.floor(downEvents.length * 0.1)); // 10% tolerance, max 2
        if (Math.abs(downEvents.length - upEvents.length) > tolerance) {
            console.warn(`Event count mismatch - Down: ${downEvents.length}, Up: ${upEvents.length}`);
            // Don't throw error, just warn and proceed with available data
        }

        // Ensure we have at least 2 characters worth of data
        if (downEvents.length < 2) {
            throw new DynamicsError('Insufficient keystroke data - need at least 2 characters', 'INSUFFICIENT_DATA'); // FIXED
        }
    }

    static #computeFeatures({ downEvents, upEvents }) {
        const features = [];
        const minLength = Math.min(downEvents.length, upEvents.length);
        
        console.log(`Computing features for ${minLength} character pairs`);

        // Sort events by timestamp to ensure correct order
        downEvents.sort((a, b) => a.timestamp - b.timestamp);
        upEvents.sort((a, b) => a.timestamp - b.timestamp);

        // Dwell times (how long each key is held down)
        for (let i = 0; i < minLength; i++) {
            // Find matching keyup for this keydown
            const keydownEvent = downEvents[i];
            const matchingKeyup = upEvents.find(up => 
                up.key === keydownEvent.key && up.timestamp > keydownEvent.timestamp
            );
            
            if (matchingKeyup) {
                const dwellTime = Math.abs(matchingKeyup.timestamp - keydownEvent.timestamp);
                const normalizedDwell = Math.min(dwellTime, 2000) / 1000; // Cap at 2 seconds, normalize to seconds
                features.push(normalizedDwell);
            } else {
                // If no matching keyup found, use average dwell time
                features.push(0.1); // 100ms default
            }
        }

        // Flight times (time between consecutive key presses)
        for (let i = 0; i < minLength - 1; i++) {
            const currentDown = downEvents[i];
            const nextDown = downEvents[i + 1];
            
            if (currentDown && nextDown) {
                const flightTime = Math.abs(nextDown.timestamp - currentDown.timestamp);
                const normalizedFlight = Math.min(flightTime, 3000) / 1000; // Cap at 3 seconds, normalize to seconds
                features.push(normalizedFlight);
            }
        }

        // Inter-key intervals (time between key release and next key press)
        for (let i = 0; i < Math.min(upEvents.length, downEvents.length - 1); i++) {
            const keyupEvent = upEvents[i];
            const nextKeydown = downEvents[i + 1];
            
            if (keyupEvent && nextKeydown && nextKeydown.timestamp > keyupEvent.timestamp) {
                const intervalTime = nextKeydown.timestamp - keyupEvent.timestamp;
                const normalizedInterval = Math.min(intervalTime, 3000) / 1000; // Cap at 3 seconds
                features.push(normalizedInterval);
            }
        }

        console.log(`Extracted ${features.length} features:`, features);

        if (features.length === 0) {
            throw new DynamicsError('No features could be extracted from keystroke data', 'NO_FEATURES'); // FIXED
        }

        return features;
    }
}

// Keystroke Capture - FIXED
class KeystrokeCapture {
    constructor() {
        this.#reset();
        this.#setupEventListeners();
    }

    #keystrokes = [];
    #isRecording = false;
    #startTime = null;
    #allowedKeys = new Set(ALLOWED_CHARS);
    #targetElement = null;
    #activeKeys = new Set(); // Track currently pressed keys

    #reset() {
        this.#keystrokes = [];
        this.#isRecording = false;
        this.#startTime = null;
        this.#targetElement = null;
        this.#activeKeys.clear();
    }

    #setupEventListeners() {
        // Use non-passive listeners but be more careful about preventDefault
        document.addEventListener('keydown', (event) => {
            this.#handleKeyEvent(event, 'keydown');
        }, { passive: false, capture: true });

        document.addEventListener('keyup', (event) => {
            this.#handleKeyEvent(event, 'keyup');
        }, { passive: false, capture: true });
    }

    #handleKeyEvent(event, eventType) {
        if (!this.#isRecording) return;

        // Only record if targeting a specific element and event comes from it
        if (this.#targetElement && event.target !== this.#targetElement) return;

        const key = Utils.normalizeKey(event.key);
        if (!this.#allowedKeys.has(key)) return;

        const timestamp = Utils.getHighResTime();
        
        // Handle keydown
        if (eventType === 'keydown') {
            // Prevent duplicate keydown events (key repeat)
            if (this.#activeKeys.has(key)) return;
            this.#activeKeys.add(key);
        } else if (eventType === 'keyup') {
            // Only record keyup if we have a corresponding keydown
            if (!this.#activeKeys.has(key)) return;
            this.#activeKeys.delete(key);
        }

        // Timeout check
        if (this.#startTime && (timestamp - this.#startTime) > CONFIG.TIMING.SAMPLE_TIMEOUT) {
            this.stopRecording();
            throw new DynamicsError('Recording timeout', 'TIMEOUT'); // FIXED
        }

        this.#keystrokes.push({
            key,
            type: eventType,
            timestamp,
            code: event.code || key,
            target: event.target.id || 'unknown'
        });

        // Debug logging
        console.log(`Recorded: ${eventType} - ${key} at ${timestamp}`);
    }

    startRecording(targetElement = null) {
        this.#reset();
        this.#isRecording = true;
        this.#startTime = Utils.getHighResTime();
        this.#targetElement = targetElement;
        console.log('Started recording keystrokes', targetElement ? `for element: ${targetElement.id}` : '(global)');
    }

    stopRecording() {
        this.#isRecording = false;
        const keystrokes = [...this.#keystrokes];
        console.log(`Stopped recording. Captured ${keystrokes.length} events:`, keystrokes);
        return keystrokes;
    }

    isRecording() {
        return this.#isRecording;
    }

    getBuffer() {
        return [...this.#keystrokes];
    }
}

// Secure Key Manager
class SecureKeyManager {
    #masterKey = null;

    setKey(key) {
        this.#masterKey = key;
    }

    getKey() {
        if (!this.#masterKey) {
            throw new DynamicsError('Master key not initialized', 'NO_MASTER_KEY');
        }
        return this.#masterKey;
    }

    clearKey() {
        this.#masterKey = null;
    }

    hasKey() {
        return this.#masterKey !== null;
    }
}

// FIXED: Main Dynamics System
class KeystrokeDynamics {
    constructor() {
        this.#validateBrowser();
        this.#database = new DynamicsDatabase();
        this.#keyManager = new SecureKeyManager();
        this.#keystrokeCapture = new KeystrokeCapture();
        this.#threshold = CONFIG.BIOMETRICS.DEFAULT_THRESHOLD;
        this.#trainingPhrase = null;
    }

    #database;
    #keyManager;
    #keystrokeCapture;
    #threshold;
    #trainingPhrase;

    #validateBrowser() {
        if (!window.indexedDB) {
            throw new Error('IndexedDB not supported in this browser');
        }
        if (!window.crypto?.subtle) {
            throw new Error('Web Crypto API not supported in this browser');
        }
    }

    // Public API
    async initialize(masterPassword, phrase) {
        try {
            this.#keyManager.setKey(masterPassword);
            this.#trainingPhrase = phrase;

            if (!this.isReady()) {
                await this.#createMasterRecord(masterPassword, phrase);
            }

            return true;
        } catch (error) {
            throw new DynamicsError(`Initialization failed: ${error.message}`, 'INIT_FAILED');
        }
    }

    async authenticate(masterPassword) {
        try {
            const phrase = await this.#loadMasterRecord(masterPassword);
            if (phrase) {
                this.#keyManager.setKey(masterPassword);
                this.#trainingPhrase = phrase;
                return phrase;
            }
            return null;
        } catch (error) {
            console.error('Authentication failed:', error);
            return null;
        }
    }

    // FIXED: Pass targetElement parameter
    startRecording(targetElement = null) {
        this.#keystrokeCapture.startRecording(targetElement);
    }

    stopRecording() {
        return this.#keystrokeCapture.stopRecording();
    }

    async addSample() {
        try {
            // Get current keystrokes and stop recording
            const keystrokes = this.stopRecording();
            
            if (keystrokes.length === 0) {
                throw new DynamicsError('No keystroke data recorded', 'NO_DATA'); // FIXED
            }

            console.log(`Adding sample with ${keystrokes.length} keystroke events`);

            const features = FeatureExtractor.extract(keystrokes);
            const signature = features.join(',');
            const encrypted = await CryptoService.encrypt(signature, this.#keyManager.getKey());

            await this.#database.save(this.#database.stores.SIGNATURES, {
                signature: encrypted,
                timestamp: Date.now(),
                phrase: this.#trainingPhrase,
                featureCount: features.length
            });

            console.log('Sample added successfully');
            return true;
        } catch (error) {
            console.error('Add sample error:', error);
            throw new DynamicsError(`Failed to add sample: ${error.message}`, 'SAMPLE_ADD_FAILED'); // FIXED
        }
    }

    async verify() {
        try {
            const keystrokes = this.stopRecording();
            if (keystrokes.length === 0) {
                throw new DynamicsError('No keystroke data recorded', 'NO_DATA');
            }

            const features = FeatureExtractor.extract(keystrokes);
            const signatures = await this.#loadAllSignatures();

            if (signatures.length < CONFIG.BIOMETRICS.MIN_SAMPLES) {
                throw new DynamicsError('Insufficient training data', 'INSUFFICIENT_SAMPLES');
            }

            const similarities = signatures.map(sig => Utils.cosineSimilarity(features, sig));
            const medianSimilarity = Utils.calculateMedian(similarities);
            const isAuthentic = medianSimilarity >= this.#threshold;

            return {
                isAuthentic,
                similarity: medianSimilarity,
                threshold: this.#threshold,
                sampleCount: signatures.length
            };
        } catch (error) {
            throw new DynamicsError(`Verification failed: ${error.message}`, 'VERIFY_FAILED');
        }
    }

    setThreshold(level) {
        if (typeof level === 'number') {
            // Direct numeric threshold (0.0 to 1.0)
            this.#threshold = Math.max(0.5, Math.min(0.95, level));
        } else {
            // String-based levels for backward compatibility
            const thresholds = {
                'low': CONFIG.BIOMETRICS.THRESHOLDS.LOW,
                'medium': CONFIG.BIOMETRICS.THRESHOLDS.MEDIUM,
                'high': CONFIG.BIOMETRICS.THRESHOLDS.HIGH,
                'max': CONFIG.BIOMETRICS.THRESHOLDS.MAX,
                '0': CONFIG.BIOMETRICS.THRESHOLDS.LOW,
                '1': CONFIG.BIOMETRICS.THRESHOLDS.MEDIUM,
                '2': CONFIG.BIOMETRICS.THRESHOLDS.HIGH,
                '3': CONFIG.BIOMETRICS.THRESHOLDS.MAX
            };
            
            this.#threshold = thresholds[level] || CONFIG.BIOMETRICS.DEFAULT_THRESHOLD;
        }
        
        console.log(`Threshold set to: ${Math.round(this.#threshold * 100)}%`);
    }

    async reset() {
        try {
            await Promise.all([
                this.#database.clear(this.#database.stores.SIGNATURES),
                this.#database.clear(this.#database.stores.MASTER),
                this.#database.clear(this.#database.stores.CREDENTIALS)
            ]);

            this.#keyManager.clearKey();
            this.#trainingPhrase = null;
            localStorage.removeItem('dynamics_system_ready'); // FIXED: renamed

            return true;
        } catch (error) {
            throw new DynamicsError(`Reset failed: ${error.message}`, 'RESET_FAILED');
        }
    }

    async clearSignatures() {
        await this.#database.clear(this.#database.stores.SIGNATURES);
    }

    // Credential Management
    async saveCredentials(site, username, password) {
        if (!this.#keyManager.hasKey()) {
            throw new DynamicsError('Master key required', 'NO_MASTER_KEY');
        }

        const credentials = { username, password };
        const encrypted = await CryptoService.encrypt(
            JSON.stringify(credentials), 
            this.#keyManager.getKey()
        );

        await this.#database.save(this.#database.stores.CREDENTIALS, {
            site,
            data: encrypted,
            timestamp: Date.now()
        });
    }

    async loadCredentials(site) {
        if (!this.#keyManager.hasKey()) {
            throw new DynamicsError('Master key required', 'NO_MASTER_KEY');
        }

        const allCreds = await this.#database.loadAll(this.#database.stores.CREDENTIALS);
        const siteCreds = allCreds.find(cred => cred.site === site);

        if (!siteCreds) return null;

        const decrypted = await CryptoService.decrypt(siteCreds.data, this.#keyManager.getKey());
        return JSON.parse(decrypted);
    }

    // Private Methods
    async #createMasterRecord(password, phrase) {
        const hashedKey = await Utils.hash256(password);
        await this.#database.save(this.#database.stores.MASTER, {
            keyHash: hashedKey,
            phrase,
            timestamp: Date.now()
        });
        localStorage.setItem('dynamics_system_ready', 'true'); // FIXED: renamed
    }

    async #loadMasterRecord(password) {
        const hashedKey = await Utils.hash256(password);
        const records = await this.#database.loadAll(this.#database.stores.MASTER);
        const record = records.find(r => r.keyHash === hashedKey);
        return record?.phrase || null;
    }

    async #loadAllSignatures() {
        if (!this.#keyManager.hasKey()) {
            throw new DynamicsError('Master key required', 'NO_MASTER_KEY');
        }

        const records = await this.#database.loadAll(this.#database.stores.SIGNATURES);
        const signatures = [];

        for (const record of records) {
            try {
                const decrypted = await CryptoService.decrypt(record.signature, this.#keyManager.getKey());
                const features = decrypted.split(',').map(Number);
                signatures.push(features);
            } catch (error) {
                console.warn('Failed to decrypt signature, skipping:', error);
            }
        }

        return signatures;
    }

    // Getters
    get phrase() {
        return this.#trainingPhrase;
    }

    get threshold() {
        return this.#threshold;
    }

    get isRecording() {
        return this.#keystrokeCapture.isRecording();
    }

    isReady() {
        return localStorage.getItem('dynamics_system_ready') === 'true'; // FIXED: renamed
    }
}

// Browser compatibility check
function checkBrowserSupport() {
    const required = [
        'indexedDB',
        'crypto.subtle',
        'performance.now',
        'TextEncoder',
        'TextDecoder'
    ];

    const missing = required.filter(feature => {
        try {
            return !eval(`window.${feature}`);
        } catch {
            return true;
        }
    });

    if (missing.length > 0) {
        throw new Error(`Browser missing required features: ${missing.join(', ')}`);
    }
}

// Initialize browser support check
try {
    checkBrowserSupport();
} catch (error) {
    console.error('Browser compatibility check failed:', error);
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        KeystrokeDynamics,
        DynamicsError,
        CryptoError,
        DatabaseError,
        CONFIG
    };
}

// Global exposure for direct script inclusion
if (typeof window !== 'undefined') {
    window.KeystrokeDynamics = KeystrokeDynamics;
    window.DynamicsError = DynamicsError;
    window.CryptoError = CryptoError;
    window.DatabaseError = DatabaseError;
}