export {};

declare global {
    interface Window {
        enableDebug?: boolean;
        KeystrokeDynamics: typeof import('./keystroke-dynamics.js').KeystrokeDynamics;
        DynamicsError: typeof import('./keystroke-dynamics.js').DynamicsError;
        CryptoError: typeof import('./keystroke-dynamics.js').CryptoError;
        DatabaseError: typeof import('./keystroke-dynamics.js').DatabaseError;
    }
}