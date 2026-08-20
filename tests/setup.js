import { IDBFactory } from 'fake-indexeddb';
import { webcrypto } from 'node:crypto';
import { performance } from 'node:perf_hooks';

// Shim missing browser APIs for jsdom
Object.defineProperty(globalThis, 'indexedDB', {
    value: new IDBFactory(),
    writable: true,
    configurable: true,
});

Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    writable: true,
    configurable: true,
});

// Use Node's native high-resolution performance.now (sub-ms precision)
Object.defineProperty(globalThis, 'performance', {
    value: performance,
    writable: true,
    configurable: true,
});