/**
 * Edge-case Tests
 * Error classes, safeStorage, CONFIG invariants
 */
import { describe, it, expect } from 'vitest';

const lib = require('../keystroke-dynamics.js');
const { KeystrokeDynamics, DynamicsError, CryptoError, DatabaseError, CONFIG } = lib;

beforeEach(() => {
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
    keys.filter(k => k && k.startsWith('dynamics_')).forEach(k => localStorage.removeItem(k));
});

describe('Error classes', () => {
    it('DynamicsError should have name and code', () => {
        const e = new DynamicsError('test message', 'TEST_CODE');
        expect(e).toBeInstanceOf(Error);
        expect(e).toBeInstanceOf(DynamicsError);
        expect(e.name).toBe('DynamicsError');
        expect(e.code).toBe('TEST_CODE');
        expect(e.message).toBe('test message');
    });

    it('CryptoError should have name and code', () => {
        const e = new CryptoError('encrypt failed', 'ENCRYPT_FAILED');
        expect(e.name).toBe('CryptoError');
        expect(e.code).toBe('ENCRYPT_FAILED');
    });

    it('DatabaseError should have name and code', () => {
        const e = new DatabaseError('db failed', 'DB_OPEN_FAILED');
        expect(e.name).toBe('DatabaseError');
        expect(e.code).toBe('DB_OPEN_FAILED');
    });

    it('DynamicsError should be thrown from verify with no data', async () => {
        const auth = new KeystrokeDynamics();
        auth.startRecording();
        auth.stopRecording();
        try {
            await auth.verify();
            expect.fail('Should have thrown');
        } catch (error) {
            expect(error).toBeInstanceOf(DynamicsError);
            expect(error.code).toBe('VERIFY_FAILED');
        }
    });
});

describe('CONFIG invariants', () => {
    it('should be frozen', () => {
        expect(Object.isFrozen(CONFIG)).toBe(true);
    });

    it('should have correct database settings', () => {
        expect(CONFIG.DATABASE.NAME).toBe('keystroke_dynamics_db');
        expect(CONFIG.DATABASE.VERSION).toBe(1);
        expect(CONFIG.DATABASE.STORES.SIGNATURES).toBe('dynamics_signatures');
        expect(CONFIG.DATABASE.STORES.MASTER).toBe('master_keys');
        expect(CONFIG.DATABASE.STORES.CREDENTIALS).toBe('user_credentials');
    });

    it('should have correct biometrics settings', () => {
        expect(CONFIG.BIOMETRICS.MIN_SAMPLES).toBe(3);
        expect(CONFIG.BIOMETRICS.MAX_SAMPLES).toBe(10);
        expect(CONFIG.BIOMETRICS.DEFAULT_THRESHOLD).toBe(0.70);
    });

    it('should have correct timing bounds', () => {
        expect(CONFIG.TIMING.MIN_DWELL_TIME).toBe(30);
        expect(CONFIG.TIMING.MAX_DWELL_TIME).toBe(500);
        expect(CONFIG.TIMING.MIN_FLIGHT_TIME).toBe(50);
        expect(CONFIG.TIMING.MAX_FLIGHT_TIME).toBe(1000);
    });
});

describe('safeStorage', () => {
    it('should survive get/set/remove cycle', () => {
        const auth = new KeystrokeDynamics();
        auth.setThreshold(0.72);
        const a2 = new KeystrokeDynamics();
        expect(a2.threshold).toBe(0.72);
        // cleanup
        localStorage.removeItem('dynamics_threshold');
    });

    it('should handle missing items gracefully', () => {
        localStorage.removeItem('dynamics_threshold');
        const auth = new KeystrokeDynamics();
        expect(auth.threshold).toBe(CONFIG.BIOMETRICS.DEFAULT_THRESHOLD);
    });

    it('should handle corrupt threshold values', () => {
        localStorage.setItem('dynamics_threshold', 'not-a-number');
        const auth = new KeystrokeDynamics();
        // Should fall back to default
        expect(auth.threshold).toBe(CONFIG.BIOMETRICS.DEFAULT_THRESHOLD);
        localStorage.removeItem('dynamics_threshold');
    });
});

describe('keyManager edge case', () => {
    it('should throw when using addSample without master key', async () => {
        const auth = new KeystrokeDynamics();
        const inp = document.createElement('input');
        document.body.appendChild(inp);
        auth.startRecording(inp);
        inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));
        inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'a', bubbles: true }));
        inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'b', bubbles: true }));
        inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'b', bubbles: true }));
        document.body.removeChild(inp);
        // No initialize() called — no master key
        await expect(auth.addSample()).rejects.toBeInstanceOf(DynamicsError);
    });
});

describe('exports', () => {
    it('should have all expected exports', () => {
        expect(KeystrokeDynamics).toBeDefined();
        expect(DynamicsError).toBeDefined();
        expect(CryptoError).toBeDefined();
        expect(DatabaseError).toBeDefined();
        expect(CONFIG).toBeDefined();
    });

    it('KeystrokeDynamics should be on window in jsdom', () => {
        expect(window.KeystrokeDynamics).toBe(KeystrokeDynamics);
    });
});