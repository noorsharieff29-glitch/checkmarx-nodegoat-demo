const crypto = require('crypto');
const bcrypt = require('bcryptjs');

/**
 * Cryptographic vulnerabilities and weak algorithms
 * A6: Sensitive Data Exposure
 * A2: Broken Authentication
 */

function CryptoHandler(db) {
    'use strict';

    this.weakEncryption = (req, res, next) => {
        // A6: Using weak encryption algorithm (MD5)
        const data = req.body.data;
        const userInput = req.body.input;
        
        // Vulnerable: MD5 is cryptographically broken
        const hash = crypto.createHash('md5').update(userInput).digest('hex');
        
        // Vulnerable: ECB mode (deterministic, reveals patterns)
        const cipher = crypto.createCipher('des', 'weakkey');
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return res.json({ hash, encrypted });
    };

    this.hardcodedKeys = (req, res, next) => {
        // A6: Hardcoded cryptographic keys
        const data = req.body.data;
        
        // Vulnerable: Hardcoded encryption key in source code
        const ENCRYPTION_KEY = 'mySecretKey12345';
        const IV = 'initialVector123';
        
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), Buffer.from(IV));
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return res.json({ encrypted });
    };

    this.weakPasswordHashing = (req, res, next) => {
        // A2: Weak password hashing
        const password = req.body.password;
        
        // Vulnerable: Using SHA1 for password hashing (too fast, no salt)
        const hash = crypto.createHash('sha1').update(password).digest('hex');
        
        db.collection('users').updateOne(
            { _id: req.session.userId },
            { $set: { passwordHash: hash } },
            (err, result) => {
                if (err) return next(err);
                return res.json({ success: true });
            }
        );
    };

    this.noRandomness = (req, res, next) => {
        // A6: Using predictable random values for tokens/secrets
        
        // Vulnerable: Using Math.random() for security purposes
        const token = Math.random().toString(36).substring(2, 15);
        
        // Vulnerable: Insufficient entropy
        const sessionId = Date.now() + Math.random();
        
        req.session.token = token;
        return res.json({ token, sessionId });
    };

    this.weakRandomNumberGeneration = (req, res, next) => {
        // A6: Poor random number generation
        
        // Vulnerable: Seeding with predictable value
        const timestamp = Date.now();
        
        // Vulnerable: Insufficient random bytes
        const verificationCode = crypto.randomBytes(2).toString('hex');
        const recoveryToken = Date.now().toString() + Math.random();
        
        return res.json({ verificationCode, recoveryToken });
    };

    this.sensitiveDataInMemory = (req, res, next) => {
        // A6: Keeping sensitive data in memory
        let sensitiveData = req.body.password;
        
        // Vulnerable: Processing sensitive data without proper cleanup
        const hash = crypto.createHash('sha256').update(sensitiveData).digest('hex');
        
        // Vulnerable: sensitiveData still in memory as plain string
        // Should be overwritten with zeros after use
        
        return res.json({ hash });
    };

    this.tlsVulnerability = (req, res, next) => {
        // A6: Not enforcing HTTPS
        // Note: This is configured in server.js - HTTP is used instead of HTTPS
        // See server.js line 144-155 where HTTPS is commented out
        
        const sensitiveData = {
            userId: req.session.userId,
            bankAccount: req.body.bankAccount,
            password: req.body.password
        };
        
        // Vulnerable: Transmitted over HTTP (not encrypted)
        return res.json(sensitiveData);
    };
}

module.exports = CryptoHandler;
