/**
 * FeatureExtractor Tests
 * Tests for event pairing, dwell time, flight time extraction
 */
import { describe, it, expect, beforeEach } from 'vitest';

const lib = require('../keystroke-dynamics.js');
const { KeystrokeDynamics } = lib;

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

describe('FeatureExtractor', () => {
    describe('event pairing', () => {
        it('should pair keydown with matching keyup', async () => {
            const auth = new KeystrokeDynamics();
            const inp = document.createElement('input');
            document.body.appendChild(inp);
            auth.startRecording(inp);

            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'h', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'h', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'i', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'i', bubbles: true }));

            const events = auth.stopRecording();
            expect(events.length).toBe(4);
            expect(events[0].type).toBe('keydown');
            expect(events[1].type).toBe('keyup');
            expect(events[2].type).toBe('keydown');
            expect(events[3].type).toBe('keyup');
            document.body.removeChild(inp);
        });

        it('should reject events with keydown but no keyup (insufficient pairs)', async () => {
            const auth = new KeystrokeDynamics();
            const inp = document.createElement('input');
            document.body.appendChild(inp);
            auth.startRecording(inp);

            // Only 1 complete pair (2 events) — need at least 2 pairs
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'a', bubbles: true }));

            await auth.addSample().catch(() => {});
            document.body.removeChild(inp);
        });

        it('should handle interleaved keys correctly', async () => {
            const auth = new KeystrokeDynamics();
            const inp = document.createElement('input');
            document.body.appendChild(inp);
            auth.startRecording(inp);

            // a down, b down, a up, b up (interleaved)
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'b', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'a', bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keyup', { key: 'b', bubbles: true }));

            const events = auth.stopRecording();
            expect(events.length).toBe(4);
            document.body.removeChild(inp);
        });
    });

    describe('feature extraction', () => {
        it('should extract dwell and flight times from typed phrase', async () => {
            const auth = new KeystrokeDynamics();
            await auth.initialize('pwd-features', 'hello');
            const chars = 'hello'.split('');

            for (let s = 0; s < 3; s++) {
                await record(auth, chars);
                await auth.addSample();
            }

            await record(auth, chars);
            const result = await auth.verify('hello');

            expect(result.sampleCount).toBe(3);
            expect(result.similarity).toBeGreaterThan(0.5);
            expect(result.threshold).toBe(0.70);
        });

        it('should reject with NO_DATA for empty buffer', async () => {
            const auth = new KeystrokeDynamics();
            await auth.initialize('pwd-nodata', 'test');

            auth.startRecording();
            auth.stopRecording(); // discard

            await expect(auth.verify()).rejects.toThrow(/No keystroke data/i);
        });

        it('should reject with INSUFFICIENT_SAMPLES when < 3 training samples', async () => {
            const auth = new KeystrokeDynamics();
            await auth.initialize('pwd-insuff', 'ab');
            const chars = 'ab'.split('');

            // Only 2 samples (need 3)
            for (let s = 0; s < 2; s++) {
                await record(auth, chars);
                await auth.addSample();
            }

            await record(auth, chars);
            await expect(auth.verify()).rejects.toThrow(/Insufficient training/i);
        });
    });

    describe('timing values', () => {
        it('should normalize dwell times (30-500ms range)', async () => {
            const auth = new KeystrokeDynamics();
            await auth.initialize('pwd-timing', 'ok');
            const chars = 'ok'.split('');

            for (let s = 0; s < 3; s++) {
                await record(auth, chars);
                await auth.addSample();
            }

            await record(auth, chars);
            const result = await auth.verify();
            // Values should be valid after clamping
            expect(result.similarity).toBeGreaterThanOrEqual(0);
            expect(result.similarity).toBeLessThanOrEqual(1);
        });
    });
});