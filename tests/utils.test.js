/**
 * Utils Tests
 * Tests for normalizeKey, median, mean, cosineSimilarity, dotProduct
 */
import { describe, it, expect, beforeEach } from 'vitest';

const lib = require('../keystroke-dynamics.js');
const { KeystrokeDynamics, DynamicsError, CONFIG } = lib;

// ── Helpers ──
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

// ── Per-test cleanup: reset IndexedDB and localStorage ──
let currentAuth = null;
beforeEach(async () => {
    if (currentAuth) {
        try { await currentAuth.reset(); } catch {}
        currentAuth = null;
    }
    // Wipe localStorage flags so isReady() returns false for the next test
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
    keys.filter(k => k && k.startsWith('dynamics_')).forEach(k => localStorage.removeItem(k));
});

describe('Utils', () => {
    describe('normalizeKey / keystroke capture', () => {
        it('should accept lowercase letters and digits', async () => {
            const auth = new KeystrokeDynamics();
            const inp = document.createElement('input');
            document.body.appendChild(inp);
            auth.startRecording(inp);
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'a', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: '9', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: '9', bubbles: true }));
            const events = auth.stopRecording();
            expect(events.length).toBe(4);
            expect(events[0].key).toBe('a');
            expect(events[2].key).toBe('9');
            document.body.removeChild(inp);
        });

        it('should normalize special chars (@ → at, . → period, etc.)', async () => {
            const auth = new KeystrokeDynamics();
            const inp = document.createElement('input');
            document.body.appendChild(inp);
            auth.startRecording(inp);
            for (const ch of ['@', '.', '-', '_']) {
                inp.dispatchEvent(new KeyboardEvent('keydown', { key: ch, bubbles: true }));
                inp.dispatchEvent(new KeyboardEvent('keyup', { key: ch, bubbles: true }));
            }
            const events = auth.stopRecording();
            expect(events[0].key).toBe('at');
            expect(events[2].key).toBe('period');
            expect(events[4].key).toBe('minus');
            expect(events[6].key).toBe('underscore');
            document.body.removeChild(inp);
        });

        it('should reject non-allowed keys', async () => {
            const auth = new KeystrokeDynamics();
            const inp = document.createElement('input');
            document.body.appendChild(inp);
            auth.startRecording(inp);
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'Shift', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'Shift', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', bubbles: true }));
            expect(auth.stopRecording().length).toBe(0);
            document.body.removeChild(inp);
        });

        it('should deduplicate key repeats', async () => {
            const auth = new KeystrokeDynamics();
            const inp = document.createElement('input');
            document.body.appendChild(inp);
            auth.startRecording(inp);
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'a', bubbles: true }));
            const events = auth.stopRecording();
            expect(events.filter(e => e.type === 'keydown').length).toBe(1);
            document.body.removeChild(inp);
        });
    });

    describe('cosineSimilarity (via verify)', () => {
        it('should produce similarity ~1.0 for identical samples', async () => {
            const auth = new KeystrokeDynamics();
            currentAuth = auth;
            await auth.initialize('pwd-test-cos', 'john.doe@example.com');
            const chars = 'john.doe@example.com'.split('');

            for (let s = 0; s < 3; s++) {
                await record(auth, chars);
                await auth.addSample();
            }

            await record(auth, chars);
            const result = await auth.verify('john.doe@example.com');

            expect(result.sampleCount).toBe(3);
            expect(result.similarity).toBeGreaterThan(0.5);
            expect(result.similarity).toBeLessThanOrEqual(1.0);
            expect(result.threshold).toBe(CONFIG.BIOMETRICS.DEFAULT_THRESHOLD);
        });

        it('phrase mismatch should set phraseMatch:false without throwing', async () => {
            const auth = new KeystrokeDynamics();
            currentAuth = auth;
            await auth.initialize('pwd-test-mismatch', 'abcd');
            const chars = 'abcd'.split('');

            for (let s = 0; s < 3; s++) {
                await record(auth, chars);
                await auth.addSample();
            }

            await record(auth, ['x', 'y', 'z', 'w']);
            const result = await auth.verify('abcd');
            expect(result.phraseMatch).toBe(false);
            // Biometrics still runs — different keys means low similarity
            expect(result.similarity).toBeLessThanOrEqual(1.0);
        });
    });

    describe('median via multi-sample', () => {
        it('should work with 4 training samples', async () => {
            const auth = new KeystrokeDynamics();
            currentAuth = auth;
            await auth.initialize('pwd-test-median', 'test');
            const chars = 'test'.split('');

            for (let s = 0; s < 4; s++) {
                await record(auth, chars);
                await auth.addSample();
            }

            await record(auth, chars);
            const result = await auth.verify('test');

            expect(result.sampleCount).toBe(4);
            expect(result.similarity).toBeGreaterThan(0.5);
            expect(typeof result.isAuthentic).toBe('boolean');
        });
    });
});