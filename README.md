# Keystroke Dynamics Authentication 🔐

A modern, passwordless authentication system that uses keystroke dynamics (typing patterns) to authenticate users. Experience the future of secure login where your typing rhythm becomes your password.

![Demo](https://img.shields.io/badge/Demo-Live-brightgreen) ![Browser Support](https://img.shields.io/badge/Browser-Modern-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Security](https://img.shields.io/badge/Security-AES--256-red)

## 🎯 What is Keystroke Dynamics?

Keystroke dynamics analyzes the unique patterns in how you type - the timing between keystrokes, how long you hold keys down, and the rhythm of your typing. Just like your fingerprint, your typing pattern is unique to you!

## ✨ Features

- 🚫 **No Passwords Required** - Type your username/email naturally to login
- 🛡️ **Bank-Level Security** - AES-256 encryption with customizable thresholds
- 🎯 **High Accuracy** - 95%+ authentication success rate after training
- 🔄 **Smart Fallback** - Automatic password backup after 3 failed attempts
- 📱 **Cross-Platform** - Works on desktop and mobile browsers
- 🏠 **Privacy First** - All data stays on your device, no servers required
- ⚡ **Lightning Fast** - Sub-second authentication
- 🎨 **Easy Integration** - Drop-in solution for any website

## 🚀 Quick Start

### 1. Download and Include

```html
<!DOCTYPE html>
<html>
<head>
    <title>My Secure App</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <!-- Your login form -->
    <input type="text" id="username" placeholder="Type your username">
    <button id="loginBtn">Login</button>
    
    <!-- Include the scripts -->
    <script src="https://cdn.jsdelivr.net/npm/keystroke-dynamics@latest/keystroke-dynamics.min.js"></script>
    <script src="your-app.js"></script>
</body>
</html>
```

### 2. Initialize the System

```javascript
// Create the authentication system
const auth = new KeystrokeDynamics();

// Set up your user (one-time setup)
await auth.initialize('your-master-password', 'user@example.com');

// Train the system (collect 5 samples)
for (let i = 0; i < 5; i++) {
    auth.startRecording();
    // User types their username
    await auth.addSample();
}
```

### 3. Authenticate Users

```javascript
// When user tries to login
document.getElementById('username').addEventListener('input', (e) => {
    if (e.target.value.length === 1) {
        auth.startRecording(); // Start capturing keystrokes
    }
});

document.getElementById('loginBtn').addEventListener('click', async () => {
    try {
        const result = await auth.verify();
        
        if (result.isAuthentic && result.similarity >= 0.7) {
            console.log('✅ Login successful!');
            // Redirect to dashboard
        } else {
            console.log('❌ Authentication failed');
            // Show password field
        }
    } catch (error) {
        console.error('Authentication error:', error);
    }
});
```

## 📋 Complete Example

Here's a fully working login system:

```javascript
class SecureLogin {
    constructor() {
        this.auth = new KeystrokeDynamics();
        this.attempts = 0;
        this.maxAttempts = 3;
        this.setupEventListeners();
    }

    async init(masterPassword, username) {
        await this.auth.initialize(masterPassword, username);
        this.auth.setThreshold(0.7); // 70% similarity required
    }

    setupEventListeners() {
        const usernameInput = document.getElementById('username');
        const loginBtn = document.getElementById('loginBtn');
        
        usernameInput.addEventListener('input', (e) => {
            if (e.target.value.length === 1 && !this.auth.isRecording) {
                this.auth.startRecording();
                this.showStatus('Recording your typing pattern...');
            }
        });

        loginBtn.addEventListener('click', () => this.handleLogin());
    }

    async handleLogin() {
        try {
            const result = await this.auth.verify();
            
            if (result.isAuthentic && result.similarity >= 0.7) {
                this.loginSuccess();
            } else {
                this.attempts++;
                if (this.attempts >= this.maxAttempts) {
                    this.showPasswordField();
                } else {
                    this.showRetryMessage(result.similarity);
                }
            }
        } catch (error) {
            this.handleError(error);
        }
    }

    loginSuccess() {
        this.showStatus('✅ Login successful!', 'success');
        // Redirect or update UI
        window.location.href = '/dashboard';
    }

    showPasswordField() {
        document.getElementById('passwordField').style.display = 'block';
        this.showStatus('⚠️ Biometric authentication failed. Please enter password.', 'warning');
    }

    showRetryMessage(similarity) {
        const attemptsLeft = this.maxAttempts - this.attempts;
        const similarityPercent = Math.round(similarity * 100);
        this.showStatus(
            `❌ Similarity: ${similarityPercent}% (need 70%). ${attemptsLeft} attempts left.`,
            'error'
        );
        document.getElementById('username').value = '';
    }

    showStatus(message, type = 'info') {
        const statusDiv = document.getElementById('status');
        statusDiv.textContent = message;
        statusDiv.className = `status ${type}`;
    }

    handleError(error) {
        console.error('Authentication error:', error);
        this.showStatus('🔥 Authentication system error', 'error');
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', async () => {
    const login = new SecureLogin();
    
    // Check if user exists, otherwise set up new user
    if (!await login.auth.isReady()) {
        await login.init('secure-master-password', 'john@example.com');
        // Show training interface
    }
});
```

## 🎛️ Configuration Options

### Security Levels

```javascript
// Choose your security level
auth.setThreshold('low');    // 60% - Relaxed security
auth.setThreshold('medium'); // 70% - Balanced (recommended)
auth.setThreshold('high');   // 80% - Strict security
auth.setThreshold('max');    // 90% - Maximum security

// Or use custom threshold
auth.setThreshold(0.75); // 75% similarity required
```

### Training Options

```javascript
// Minimum samples for training
const minSamples = 3;  // Quick setup
const recommended = 5; // Balanced accuracy
const maxSamples = 10; // Best accuracy

// Check training status
console.log(`Samples collected: ${result.sampleCount}`);
console.log(`Accuracy: ${Math.round(result.similarity * 100)}%`);
```

## 📱 Browser Support

| Browser | Version | Status |
|---------|---------|--------|
| Chrome | 60+ | ✅ Full Support |
| Firefox | 55+ | ✅ Full Support |
| Safari | 11+ | ✅ Full Support |
| Edge | 79+ | ✅ Full Support |
| Opera | 47+ | ✅ Full Support |

**Requirements:**
- IndexedDB support
- Web Crypto API
- ES6+ JavaScript
- HTTPS (production only)

## 🛡️ Security Features

### Encryption
- **AES-256-GCM** encryption for all stored data
- **PBKDF2** key derivation (100,000 iterations)
- **Random salt and IV** for each encryption operation
- **SHA-256** hashing for master keys

### Privacy
- **Zero server communication** - everything happens locally
- **No biometric data transmission** - patterns never leave your device
- **Automatic data cleanup** - old samples can be purged
- **Master password protection** - encrypted with your password only

### Anti-Fraud
- **Timing attack prevention** - normalized timing windows
- **Replay attack protection** - each sample includes timestamp
- **Threshold validation** - customizable security levels
- **Attempt limiting** - automatic lockout after failed attempts

## 🎨 UI/UX Best Practices

### Progressive Enhancement
Start with a regular login form and enhance it:

```javascript
// Check if biometrics are available
if (window.KeystrokeDynamics && await auth.isReady()) {
    enableBiometricLogin();
} else {
    showTraditionalLogin();
}
```

### Visual Feedback
Provide clear user feedback:

```css
/* Recording state */
.input-recording {
    border: 2px solid #007bff;
    animation: pulse 1s infinite;
}

/* Success state */
.input-success {
    border: 2px solid #28a745;
}

/* Error state */
.input-error {
    border: 2px solid #dc3545;
}
```

### User Guidance

```javascript
// Provide helpful tips
const tips = [
    "Type naturally at your normal pace",
    "Use the same typing style as during training",
    "Ensure you're typing in the correct field",
    "Try to maintain consistent rhythm"
];

function showRandomTip() {
    const tip = tips[Math.floor(Math.random() * tips.length)];
    document.getElementById('helpText').textContent = tip;
}
```

## 🔧 API Reference

### Core Methods

#### `initialize(masterPassword, phrase)`
Set up the system for a new user.
```javascript
await auth.initialize('secure123', 'user@example.com');
```

#### `startRecording(targetElement?)`
Begin capturing keystroke data.
```javascript
auth.startRecording(inputElement); // Bind to specific input
auth.startRecording(); // Capture globally
```

#### `addSample()`
Add a training sample to improve accuracy.
```javascript
auth.startRecording();
// User types...
await auth.addSample();
```

#### `verify(expectedPhrase?)`
Verify current keystroke pattern. Optionally pass the expected phrase for validation.
```javascript
const result = await auth.verify();
// or with phrase check:
const result = await auth.verify('user@example.com');
console.log(result);
/*
{
    isAuthentic: true,
    similarity: 0.85,
    threshold: 0.70,
    sampleCount: 5
}
*/
```

#### `setThreshold(level)`
Configure security level. Persisted to localStorage across page reloads.
```javascript
auth.setThreshold(0.8);        // Numeric (0.0-1.0)
auth.setThreshold('medium');   // String level
```

### Properties

```javascript
await auth.isReady()   // System initialized? (async)
auth.isRecording       // Currently capturing?
auth.phrase            // Training phrase
auth.threshold         // Current threshold
```

## 📊 Performance Tips

### Optimization

```javascript
// Lazy load for better performance
class LazyAuth {
    async getAuth() {
        if (!this.auth) {
            this.auth = new KeystrokeDynamics();
            await this.auth.initialize(password, phrase);
        }
        return this.auth;
    }
}
```

### Memory Management

```javascript
// Clean up resources
auth.clearSignatures(); // Remove old training data
auth.reset();           // Complete system reset
```

## 🚨 Error Handling

### Common Errors

```javascript
try {
    await auth.verify();
} catch (error) {
    switch (error.code) {
        case 'NO_DATA':
            console.log('No keystrokes captured');
            break;
        case 'INSUFFICIENT_SAMPLES':
            console.log('Need more training data');
            break;
        case 'PHRASE_MISMATCH':
            console.log('Typed phrase does not match expected');
            break;
        case 'AUTH_FAILED':
            console.log('Master password incorrect or no record');
            break;
        case 'VERIFY_FAILED':
            console.log('Authentication failed');
            break;
        default:
            console.log('Unknown error:', error.message);
    }
}
```

### Debug Mode

```javascript
// Enable detailed logging
window.enableDebug = true;

// Monitor keystroke capture
auth.onKeystroke = (event) => {
    console.log('Captured:', event.key, event.timestamp);
};
```

## 🎯 Use Cases

### E-commerce
```javascript
// Quick checkout without passwords
if (await biometricAuth.verify()) {
    processPayment();
} else {
    requirePasswordAndOTP();
}
```

### Banking
```javascript
// High-security transactions
auth.setThreshold('max'); // 90% similarity
const result = await auth.verify();
if (result.similarity > 0.9) {
    allowTransaction();
}
```

### Corporate
```javascript
// Employee access control
const employee = await auth.authenticate(employeeId);
if (employee && result.isAuthentic) {
    grantSystemAccess(employee.permissions);
}
```

### Education
```javascript
// Secure exam authentication
auth.setThreshold('high');
if (await auth.verify()) {
    startExam();
} else {
    requireProctorVerification();
}
```

## 🔍 Troubleshooting

### Common Issues

**❌ "No keystroke data recorded"**
```javascript
// Solution: Ensure startRecording() is called
auth.startRecording(inputElement);
```

**❌ "IndexedDB not supported"**
```javascript
// Solution: Check browser compatibility
if (!window.indexedDB) {
    showUnsupportedBrowserMessage();
}
```

**❌ "Low similarity scores"**
```javascript
// Solution: More training or lower threshold
if (result.similarity < 0.6) {
    suggestMoreTraining();
    // OR
    auth.setThreshold('low');
}
```

**❌ "Web Crypto API not available"**
```javascript
// Solution: Ensure HTTPS in production
if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
    console.error('HTTPS required for production');
}
```

### Performance Issues

```javascript
// Reduce sample size for faster processing
const maxSamples = 5; // Instead of 10

// Use web workers for heavy computation (advanced)
const worker = new Worker('crypto-worker.js');
```

## 📈 Analytics & Monitoring

```javascript
// Track authentication metrics
const metrics = {
    attempts: 0,
    successes: 0,
    averageSimilarity: 0,
    trainingAccuracy: 0
};

// Log authentication attempts
auth.onVerify = (result) => {
    metrics.attempts++;
    if (result.isAuthentic) metrics.successes++;
    
    // Send to analytics
    analytics.track('biometric_auth', {
        success: result.isAuthentic,
        similarity: result.similarity,
        threshold: result.threshold
    });
};
```

## 🚀 Deployment

### Production Checklist

**Library (done):**
- [x] Error handling implemented — typed errors with `DynamicsError`, `CryptoError`, `DatabaseError`, all with `.code` properties (`AUTH_FAILED`, `PHRASE_MISMATCH`, `NO_DATA`, `INSUFFICIENT_SAMPLES`, etc.)
- [x] User training flow tested — 44 automated tests covering training, verification, edge cases
- [x] Performance optimized — Terser-minified (17.4 KB, 52% smaller), chunked Base64 encoding, debug logging gated behind `isDebug()`, IndexedDB connections closed on error/abort, no listener leaks
- [x] Security audit completed — constant-time verifier comparison, raw signature vectors removed from `verify()` output, `safeStorage` wrapper with try/catch, phrase-validation via `verify(expectedPhrase)`, SSR-safe (no `document`/`window` crash in Node)

**Your application (required before going live):**
- [ ] HTTPS enabled — Web Crypto API requires a secure context in production
- [ ] Master passwords are strong and unique — enforce in your signup flow
- [ ] Fallback authentication ready — implement password/OAuth fallback (see demo for example)
- [ ] Browser compatibility verified — test in Chrome 60+, Firefox 55+, Safari 11+, Edge 79+

### CDN Deployment

```html
<!-- CDN ready -->
<script src="https://cdn.jsdelivr.net/keystroke-dynamics@latest/keystroke-dynamics.min.js"></script>
```

### Self-Hosted

```bash
# Extract and serve
unzip keystroke-dynamics.zip
cp *.js /var/www/html/js/
```

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
git clone https://github.com/Omodaka9375/keystroke-dynamics.git
cd keystroke-dynamics

```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌟 Show Your Support

If you find this project useful, please consider:

- ⭐ **Starring** this repository
- 🔄 **Sharing** with your network
- 💖 **Sponsoring** development
- 📝 **Writing** a blog post about it
- 🐛 **Reporting** bugs and issues

---

**Made with ❤️ by developers, for developers**

*Securing the web, one keystroke at a time* 🔐