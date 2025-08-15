/**
 * Keystroke Dynamics Authentication System
 * Passwordless Web Authentication - FIXED SIMILARITY CALCULATION
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
        DEFAULT_THRESHOLD: 0.70,
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
        SAMPLE_TIMEOUT: 30000,
        MIN_DWELL_TIME: 30,      // 30ms minimum dwell
        MAX_DWELL_TIME: 500,     // 500ms maximum dwell
        MIN_FLIGHT_TIME: 50,     // 50ms minimum flight
        MAX_FLIGHT_TIME: 1000,   // 1 second maximum flight
        DEFAULT_DWELL: 0.1,      // 100ms default
        DEFAULT_FLIGHT: 0.2      // 200ms default
    }
});

// Simplified allowed characters (only what we actually use)
const ALLOWED_CHARS = Object.freeze([
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9',
    'at', 'period', 'minus', 'underscore', 'space'
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

// Utility Functions - CLEANED UP
const Utils = {
    getHighResTime() {
        return performance.now ? performance.now() : Date.now();
    },

    buffToBase64(buffer) {
        return btoa(String.fromCharCode.apply(null, buffer));
    },

    base64ToBuff(base64) {
        return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    },

    // SIMPLIFIED: Only handle the keys we actually need
    normalizeKey(key) {
        if (!key || typeof key !== 'string') return '';
        
        const keyMap = {
            '.': 'period',
            '@': 'at',
            '-': 'minus',
            '_': 'underscore',
            ' ': 'space'
        };
        
        return keyMap[key] || key.toLowerCase();
    },

    isValidChar(char) {
        const normalized = this.normalizeKey(char);
        return ALLOWED_CHARS.includes(normalized);
    },

    // FIXED: Better statistical calculations
    calculateMedian(values) {
        if (!values || values.length === 0) return 0;
        const valid = values.filter(v => typeof v === 'number' && !isNaN(v) && isFinite(v));
        if (valid.length === 0) return 0;
        
        const sorted = [...valid].sort((a, b) => a - b);
        const middle = Math.floor(sorted.length / 2);
        return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
    },

    calculateMean(values) {
        if (!values || values.length === 0) return 0;
        const valid = values.filter(v => typeof v === 'number' && !isNaN(v) && isFinite(v));
        if (valid.length === 0) return 0;
        return valid.reduce((sum, val) => sum + val, 0) / valid.length;
    },

    // FIXED: Enhanced dot product with proper validation
    dotProduct(a, b) {
        if (!Array.isArray(a) || !Array.isArray(b)) {
            console.warn('Invalid input to dotProduct - not arrays');
            return 0;
        }
        
        if (a.length !== b.length) {
            console.warn(`Vector length mismatch: ${a.length} vs ${b.length}`);
            return 0;
        }
        
        let sum = 0;
        for (let i = 0; i < a.length; i++) {
            const valA = (typeof a[i] === 'number' && !isNaN(a[i])) ? a[i] : 0;
            const valB = (typeof b[i] === 'number' && !isNaN(b[i])) ? b[i] : 0;
            sum += valA * valB;
        }
        
        return sum;
    },

    // FIXED: Enhanced cosine similarity with detailed debugging
    cosineSimilarity(a, b) {
        try {
            // Input validation
            if (!Array.isArray(a) || !Array.isArray(b)) {
                console.error('Cosine similarity: inputs must be arrays');
                return 0;
            }

            if (a.length === 0 || b.length === 0) {
                console.error('Cosine similarity: empty arrays provided');
                return 0;
            }

            if (a.length !== b.length) {
                console.error(`Cosine similarity: length mismatch ${a.length} vs ${b.length}`);
                return 0;
            }

            console.log('=== COSINE SIMILARITY DEBUG ===');
            console.log('Vector A (length:', a.length, '):', a);
            console.log('Vector B (length:', b.length, '):', b);

            // Calculate dot product and magnitudes
            const dotProd = this.dotProduct(a, b);
            const magA = Math.sqrt(this.dotProduct(a, a));
            const magB = Math.sqrt(this.dotProduct(b, b));

            console.log('Dot product A·B:', dotProd);
            console.log('Magnitude |A|:', magA);
            console.log('Magnitude |B|:', magB);

            // Check for zero magnitude vectors
            if (magA === 0) {
                console.error('Vector A has zero magnitude');
                return 0;
            }
            
            if (magB === 0) {
                console.error('Vector B has zero magnitude'); 
                return 0;
            }

            // Calculate similarity
            const similarity = dotProd / (magA * magB);
            console.log('Raw similarity:', similarity);

            // Validate result
            if (isNaN(similarity) || !isFinite(similarity)) {
                console.error('Invalid similarity result:', similarity);
                return 0;
            }

            // Clamp to valid range [-1, 1]
            const clampedSimilarity = Math.max(-1, Math.min(1, similarity));
            console.log('Final similarity:', clampedSimilarity);
            console.log('=== END COSINE SIMILARITY DEBUG ===');
            
            return clampedSimilarity;
            
        } catch (error) {
            console.error('Cosine similarity calculation failed:', error);
            return 0;
        }
    },

    async hash256(data) {
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
};

// Cryptography Service (unchanged)
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

// Database Service (unchanged)
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

// COMPLETELY REWRITTEN: Feature Extractor with proper event pairing
class FeatureExtractor {
    static extract(keystrokes) {
        console.log('=== FEATURE EXTRACTION DEBUG ===');
        console.log('Input keystrokes:', keystrokes.length, 'events');
        
        if (!keystrokes || keystrokes.length === 0) {
            throw new DynamicsError('No keystroke data provided', 'NO_DATA');
        }

        // Create proper event pairs
        const eventPairs = this.#createEventPairs(keystrokes);
        console.log('Created event pairs:', eventPairs.length);
        
        if (eventPairs.length < 2) {
            throw new DynamicsError('Need at least 2 complete keystroke pairs', 'INSUFFICIENT_PAIRS');
        }
        
        // Extract features from pairs
        const features = this.#extractTimingFeatures(eventPairs);
        
        console.log('Final feature vector:', features);
        console.log('Feature count:', features.length);
        console.log('=== END FEATURE EXTRACTION DEBUG ===');
        
        return features;
    }

    // FIXED: Create proper keydown-keyup pairs
    static #createEventPairs(keystrokes) {
        const pairs = [];
        const downEvents = keystrokes.filter(e => e.type === 'keydown').sort((a, b) => a.timestamp - b.timestamp);
        const upEvents = keystrokes.filter(e => e.type === 'keyup').sort((a, b) => a.timestamp - b.timestamp);
        
        console.log('Down events:', downEvents.map(e => `${e.key}@${Math.round(e.timestamp)}`));
        console.log('Up events:', upEvents.map(e => `${e.key}@${Math.round(e.timestamp)}`));
        
        // For each keydown, find the next keyup of the same key
        for (const downEvent of downEvents) {
            const matchingUpEvent = upEvents.find(upEvent => 
                upEvent.key === downEvent.key && 
                upEvent.timestamp > downEvent.timestamp
            );
            
            if (matchingUpEvent) {
                pairs.push({
                    key: downEvent.key,
                    downTime: downEvent.timestamp,
                    upTime: matchingUpEvent.timestamp,
                    dwellTime: matchingUpEvent.timestamp - downEvent.timestamp
                });
                
                // Remove the used up event to avoid duplicate pairing
                const upIndex = upEvents.indexOf(matchingUpEvent);
                if (upIndex > -1) {
                    upEvents.splice(upIndex, 1);
                }
            }
        }
        
        // Sort pairs by downTime to maintain order
        pairs.sort((a, b) => a.downTime - b.downTime);
        
        console.log('Event pairs created:', pairs.map(p => 
            `${p.key}: dwell=${Math.round(p.dwellTime)}ms`
        ));
        
        return pairs;
    }

    // FIXED: Extract consistent timing features
    static #extractTimingFeatures(eventPairs) {
        const features = [];
        
        // Dwell times (how long each key is held)
        for (const pair of eventPairs) {
            let dwellTime = pair.dwellTime;
            
            // Clamp to reasonable bounds
            dwellTime = Math.max(CONFIG.TIMING.MIN_DWELL_TIME, 
                        Math.min(dwellTime, CONFIG.TIMING.MAX_DWELL_TIME));
            
            // Convert to seconds and ensure minimum value
            const normalizedDwell = Math.max(0.001, dwellTime / 1000);
            features.push(normalizedDwell);
            
            console.log(`Dwell time for '${pair.key}': ${dwellTime}ms -> ${normalizedDwell}s`);
        }
        
        // Flight times (time between consecutive key presses)
        for (let i = 0; i < eventPairs.length - 1; i++) {
            const currentPair = eventPairs[i];
            const nextPair = eventPairs[i + 1];
            
            // Flight time = time from current key press to next key press
            let flightTime = nextPair.downTime - currentPair.downTime;
            
            // Clamp to reasonable bounds
            flightTime = Math.max(CONFIG.TIMING.MIN_FLIGHT_TIME,
                         Math.min(flightTime, CONFIG.TIMING.MAX_FLIGHT_TIME));
            
            // Convert to seconds and ensure minimum value
            const normalizedFlight = Math.max(0.001, flightTime / 1000);
            features.push(normalizedFlight);
            
            console.log(`Flight time ${currentPair.key} -> ${nextPair.key}: ${flightTime}ms -> ${normalizedFlight}s`);
        }
        
        // Validate features
        if (features.length === 0) {
            throw new DynamicsError('No timing features extracted', 'NO_FEATURES');
        }
        
        // Check for invalid values
        const invalidFeatures = features.filter(f => !Number.isFinite(f) || f <= 0);
        if (invalidFeatures.length > 0) {
            console.warn('Invalid features detected:', invalidFeatures);
            // Replace invalid features with defaults
            for (let i = 0; i < features.length; i++) {
                if (!Number.isFinite(features[i]) || features[i] <= 0) {
                    features[i] = i % 2 === 0 ? CONFIG.TIMING.DEFAULT_DWELL : CONFIG.TIMING.DEFAULT_FLIGHT;
                }
            }
        }
        
        console.log('Final validated features:', features);
        return features;
    }
}

// Keystroke Capture (unchanged)
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
    #activeKeys = new Set();

    #reset() {
        this.#keystrokes = [];
        this.#isRecording = false;
        this.#startTime = null;
        this.#targetElement = null;
        this.#activeKeys.clear();
    }

    #setupEventListeners() {
        document.addEventListener('keydown', (event) => {
            this.#handleKeyEvent(event, 'keydown');
        }, { passive: false, capture: true });

        document.addEventListener('keyup', (event) => {
            this.#handleKeyEvent(event, 'keyup');
        }, { passive: false, capture: true });
    }

    #handleKeyEvent(event, eventType) {
        if (!this.#isRecording) return;
        if (this.#targetElement && event.target !== this.#targetElement) return;

        const key = Utils.normalizeKey(event.key);
        if (!this.#allowedKeys.has(key)) return;

        const timestamp = Utils.getHighResTime();
        
        if (eventType === 'keydown') {
            if (this.#activeKeys.has(key)) return; // Prevent key repeat
            this.#activeKeys.add(key);
        } else if (eventType === 'keyup') {
            if (!this.#activeKeys.has(key)) return; // Only record if we have keydown
            this.#activeKeys.delete(key);
        }

        if (this.#startTime && (timestamp - this.#startTime) > CONFIG.TIMING.SAMPLE_TIMEOUT) {
            this.stopRecording();
            throw new DynamicsError('Recording timeout', 'TIMEOUT');
        }

        this.#keystrokes.push({
            key,
            type: eventType,
            timestamp,
            code: event.code || key,
            target: event.target.id || 'unknown'
        });

        console.log(`Recorded: ${eventType} - ${key} at ${Math.round(timestamp)}`);
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
        console.log(`Stopped recording. Captured ${keystrokes.length} events`);
        return keystrokes;
    }

    isRecording() {
        return this.#isRecording;
    }

    getBuffer() {
        return [...this.#keystrokes];
    }
}

// Secure Key Manager (unchanged)
class SecureKeyManager {
    #masterKey = null;

    setKey(key) { this.#masterKey = key; }
    getKey() {
        if (!this.#masterKey) throw new DynamicsError('Master key not initialized', 'NO_MASTER_KEY');
        return this.#masterKey;
    }
    clearKey() { this.#masterKey = null; }
    hasKey() { return this.#masterKey !== null; }
}

// CLEANED UP: Main Keystroke Dynamics System
class KeystrokeDynamics {
    #database;
    #keyManager;
    #keystrokeCapture;
    #threshold;
    #trainingPhrase;

    constructor() {
        this.#validateBrowser();
        this.#database = new DynamicsDatabase();
        this.#keyManager = new SecureKeyManager();
        this.#keystrokeCapture = new KeystrokeCapture();
        this.#threshold = CONFIG.BIOMETRICS.DEFAULT_THRESHOLD;
        this.#trainingPhrase = null;
    }

    #validateBrowser() {
        if (!window.indexedDB) throw new Error('IndexedDB not supported in this browser');
        if (!window.crypto?.subtle) throw new Error('Web Crypto API not supported in this browser');
    }

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

    startRecording(targetElement = null) {
        this.#keystrokeCapture.startRecording(targetElement);
    }

    stopRecording() {
        return this.#keystrokeCapture.stopRecording();
    }

    async addSample() {
        try {
            const keystrokes = this.stopRecording();
            if (keystrokes.length === 0) {
                throw new DynamicsError('No keystroke data recorded', 'NO_DATA');
            }

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
            throw new DynamicsError(`Failed to add sample: ${error.message}`, 'SAMPLE_ADD_FAILED');
        }
    }

    async verify() {
        try {
            const keystrokes = this.stopRecording();
            if (keystrokes.length === 0) {
                throw new DynamicsError('No keystroke data recorded', 'NO_DATA');
            }

            console.log('=== VERIFICATION DEBUG ===');
            const features = FeatureExtractor.extract(keystrokes);
            const signatures = await this.#loadAllSignatures();
            
            if (signatures.length < CONFIG.BIOMETRICS.MIN_SAMPLES) {
                throw new DynamicsError('Insufficient training data', 'INSUFFICIENT_SAMPLES');
            }

            console.log('Current features:', features);
            console.log('Stored signatures:', signatures);

            const similarities = signatures.map((sig, index) => {
                console.log(`\n--- Comparing with signature ${index} ---`);
                const similarity = Utils.cosineSimilarity(features, sig);
                console.log(`Similarity ${index}: ${similarity}`);
                return similarity;
            });

            const medianSimilarity = Utils.calculateMedian(similarities);
            const maxSimilarity = Math.max(...similarities);
            
            console.log('\n=== VERIFICATION RESULTS ===');
            console.log('All similarities:', similarities);
            console.log('Median similarity:', medianSimilarity);
            console.log('Max similarity:', maxSimilarity);
            console.log('Threshold:', this.#threshold);
            console.log('Is authentic:', medianSimilarity >= this.#threshold);
            console.log('=== END VERIFICATION DEBUG ===');

            return {
                isAuthentic: medianSimilarity >= this.#threshold,
                similarity: medianSimilarity,
                threshold: this.#threshold,
                sampleCount: signatures.length,
                debug: {
                    similarities,
                    max: maxSimilarity,
                    features,
                    signatures
                }
            };
        } catch (error) {
            console.error('Verification error:', error);
            throw new DynamicsError(`Verification failed: ${error.message}`, 'VERIFY_FAILED');
        }
    }

    setThreshold(level) {
        if (typeof level === 'number') {
            this.#threshold = Math.max(0.1, Math.min(0.95, level));
        } else {
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
            localStorage.removeItem('dynamics_system_ready');
            return true;
        } catch (error) {
            throw new DynamicsError(`Reset failed: ${error.message}`, 'RESET_FAILED');
        }
    }

    async clearSignatures() {
        await this.#database.clear(this.#database.stores.SIGNATURES);
    }

    async #createMasterRecord(password, phrase) {
        const hashedKey = await Utils.hash256(password);
        await this.#database.save(this.#database.stores.MASTER, {
            keyHash: hashedKey,
            phrase,
            timestamp: Date.now()
        });
        localStorage.setItem('dynamics_system_ready', 'true');
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
                const features = decrypted.split(',').map(str => {
                    const num = parseFloat(str);
                    return Number.isFinite(num) ? num : 0.1; // Default value for invalid numbers
                });
                signatures.push(features);
            } catch (error) {
                console.warn('Failed to decrypt signature, skipping:', error);
            }
        }

        return signatures;
    }

    // Credential management methods (unchanged but cleaned up)
    async saveCredentials(site, username, password) {
        if (!this.#keyManager.hasKey()) throw new DynamicsError('Master key required', 'NO_MASTER_KEY');
        const credentials = { username, password };
        const encrypted = await CryptoService.encrypt(JSON.stringify(credentials), this.#keyManager.getKey());
        await this.#database.save(this.#database.stores.CREDENTIALS, { site, data: encrypted, timestamp: Date.now() });
    }

    async loadCredentials(site) {
        if (!this.#keyManager.hasKey()) throw new DynamicsError('Master key required', 'NO_MASTER_KEY');
        const allCreds = await this.#database.loadAll(this.#database.stores.CREDENTIALS);
        const siteCreds = allCreds.find(cred => cred.site === site);
        if (!siteCreds) return null;
        const decrypted = await CryptoService.decrypt(siteCreds.data, this.#keyManager.getKey());
        return JSON.parse(decrypted);
    }

    // Getters
    get phrase() { return this.#trainingPhrase; }
    get threshold() { return this.#threshold; }
    get isRecording() { return this.#keystrokeCapture.isRecording(); }
    isReady() { return localStorage.getItem('dynamics_system_ready') === 'true'; }
}

// Browser compatibility check
function checkBrowserSupport() {
    const required = ['indexedDB', 'crypto.subtle', 'performance.now', 'TextEncoder', 'TextDecoder'];
    const missing = required.filter(feature => {
        try { return !eval(`window.${feature}`); } catch { return true; }
    });
    if (missing.length > 0) {
        throw new Error(`Browser missing required features: ${missing.join(', ')}`);
    }
}

try {
    checkBrowserSupport();
} catch (error) {
    console.error('Browser compatibility check failed:', error);
}

// Exports
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { KeystrokeDynamics, DynamicsError, CryptoError, DatabaseError, CONFIG };
}

if (typeof window !== 'undefined') {
    window.KeystrokeDynamics = KeystrokeDynamics;
    window.DynamicsError = DynamicsError;
    window.CryptoError = CryptoError;
    window.DatabaseError = DatabaseError;
}