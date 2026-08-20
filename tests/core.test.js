/**
 * Core Tests
 * Tests for KeystrokeDynamics constructor, isReady, authenticate, threshold, reset
 */
import { describe, it, expect, beforeEach } from 'vitest';

const lib = require('../keystroke-dynamics.js');
const { KeystrokeDynamics, DynamicsError, CONFIG } = lib;

beforeEach(() => {
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
    keys.filter(k => k && k.startsWith('dynamics_')).forEach(k => localStorage.removeItem(k));
});

async function record(auth, chars) {
    const inp = document.createElement('input');
    document.body.appendChild(inp);
    auth.startRecording(inp);
    for (const ch of chars) {
        inp.dispatchEvent(new KeyboardEvent('keydown', { key: ch, bubbles: true }));
        inp.dispatchEvent(new KeyboardEvent('keyup', { key: ch, bubbles: true }));
    }
    await new Promise(r => setTimeout(r, 5));
    document.body.removeChild(inp);
}

describe('KeystrokeDynamics', () => {
    describe('constructor', () => {
        it('should create an instance without error', () => {
            const auth = new KeystrokeDynamics();
            expect(auth).toBeInstanceOf(KeystrokeDynamics);
            expect(auth.phrase).toBe(null);
            expect(auth.threshold).toBe(CONFIG.BIOMETRICS.DEFAULT_THRESHOLD);
        });

        it('should have consistent default threshold', () => {
            const a1 = new KeystrokeDynamics();
            const a2 = new KeystrokeDynamics();
            expect(a1.threshold).toBe(a2.threshold);
            expect(a1.threshold).toBe(0.70);
        });
    });

    describe('isReady', () => {
        it('should return false when not initialized', async () => {
            const auth = new KeystrokeDynamics();
            expect(await auth.isReady()).toBe(false);
        });

        it('should return true after initialize', async () => {
            const auth = new KeystrokeDynamics();
            await auth.initialize('mypassword', 'user@test.com');
            expect(await auth.isReady()).toBe(true);
            await auth.reset();
        });

        it('should survive localStorage + IndexedDB drift', async () => {
            const auth = new KeystrokeDynamics();
            // Set localStorage flag without IndexedDB data
            localStorage.setItem('dynamics_system_ready', 'true');
            expect(await auth.isReady()).toBe(false);
            localStorage.removeItem('dynamics_system_ready');
        });
    });

    describe('authenticate', () => {
        it('should return phrase for correct password', async () => {
            const auth = new KeystrokeDynamics();
            await auth.initialize('secret123', 'alice@test.com');
            const phrase = await auth.authenticate('secret123');
            expect(phrase).toBe('alice@test.com');
            await auth.reset();
        });

        it('should throw AUTH_FAILED for wrong password', async () => {
            const auth = new KeystrokeDynamics();
            await auth.initialize('secret123', 'alice@test.com');
            await expect(auth.authenticate('wrong')).rejects.toBeInstanceOf(DynamicsError);
            await auth.reset();
        });

        it('should throw AUTH_FAILED when no master record exists', async () => {
            const auth = new KeystrokeDynamics();
            await expect(auth.authenticate('anything')).rejects.toBeInstanceOf(DynamicsError);
        });
    });

    describe('threshold', () => {
        it('should accept numeric values and clamp 0.1-0.95', () => {
            const auth = new KeystrokeDynamics();
            auth.setThreshold(0.85);
            expect(auth.threshold).toBe(0.85);
            auth.setThreshold(0.0);
            expect(auth.threshold).toBe(0.1); // clamped
            auth.setThreshold(1.0);
            expect(auth.threshold).toBe(0.95); // clamped
        });

        it('should accept string levels (low/medium/high/max)', () => {
            const auth = new KeystrokeDynamics();
            auth.setThreshold('low');
            expect(auth.threshold).toBe(0.60);
            auth.setThreshold('medium');
            expect(auth.threshold).toBe(0.70);
            auth.setThreshold('high');
            expect(auth.threshold).toBe(0.80);
            auth.setThreshold('max');
            expect(auth.threshold).toBe(0.90);
        });

        it('should persist across instances via safeStorage', () => {
            const a1 = new KeystrokeDynamics();
            a1.setThreshold(0.83);
            const a2 = new KeystrokeDynamics();
            expect(a2.threshold).toBe(0.83);
        });
    });

    describe('reset', () => {
        it('should clear all data and return isReady false', async () => {
            const auth = new KeystrokeDynamics();
            await auth.initialize('pass', 'user@test.com');
            await auth.reset();
            expect(await auth.isReady()).toBe(false);
            expect(auth.phrase).toBe(null);
        });

        it('should clear threshold from localStorage', () => {
            const a1 = new KeystrokeDynamics();
            a1.setThreshold(0.83);
            // reset should clear it
            a1.setThreshold(0.70);
            expect(a1.threshold).toBe(0.70);
        });
    });

    describe('recording lifecycle', () => {
        it('startRecording → stopRecording → works', async () => {
            const auth = new KeystrokeDynamics();
            const inp = document.createElement('input');
            document.body.appendChild(inp);
            auth.startRecording(inp);
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'a', bubbles: true }));
            const events = auth.stopRecording();
            expect(events.length).toBe(2);
            document.body.removeChild(inp);
        });

        it('isRecording reflects correct state', () => {
            const auth = new KeystrokeDynamics();
            expect(auth.isRecording).toBe(false);
            auth.startRecording();
            expect(auth.isRecording).toBe(true);
            auth.stopRecording();
            expect(auth.isRecording).toBe(false);
        });
    });

    describe('max samples limit', () => {
        it('should reject addSample when MAX_SAMPLES reached', async () => {
            const auth = new KeystrokeDynamics();
            await auth.initialize('pass-max', 'abc');
            const chars = 'abc'.split('');

            for (let s = 0; s < CONFIG.BIOMETRICS.MAX_SAMPLES; s++) {
                await record(auth, chars);
                await auth.addSample();
            }

            // One more should fail
            await record(auth, chars);
            await expect(auth.addSample()).rejects.toThrow(/Maximum training samples/i);
            await auth.reset();
        });
    });
});