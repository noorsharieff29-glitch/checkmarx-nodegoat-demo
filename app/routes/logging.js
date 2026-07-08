/**
 * Logging and monitoring vulnerabilities
 * A10: Security Misconfiguration
 * A6: Sensitive Data Exposure
 */

function LoggingHandler(db) {
    'use strict';

    this.insufficientLogging = (req, res, next) => {
        // A10: Insufficient logging of security events
        const username = req.body.username;
        const password = req.body.password;
        
        // Vulnerable: No logging of failed login attempts
        if (username === 'admin' && password === 'wrongpassword') {
            // Attacker can attempt unlimited login tries without detection
            return res.json({ success: false });
        }
        
        // Vulnerable: Minimal logging of successful logins
        console.log('User logged in');
        return res.json({ success: true });
    };

    this.sensitiveDataLogging = (req, res, next) => {
        // A6 + A10: Logging sensitive data
        const user = req.body.user;
        
        // Vulnerable: Logging full user objects with sensitive data
        console.log('User data received:', user);
        console.log('Password:', user.password);
        console.log('Credit Card:', user.creditCard);
        console.log('SSN:', user.ssn);
        
        // Vulnerable: Sensitive data in error messages
        const error = new Error(`Failed to process user ${user.email} with password ${user.password}`);
        console.error(error);
        
        return res.json({ success: true });
    };

    this.missingSecurityHeaders = (req, res, next) => {
        // A10: Missing security headers
        // Note: These should be set in server.js middleware but are commented out
        // - X-Frame-Options (Clickjacking protection)
        // - X-Content-Type-Options (MIME type sniffing)
        // - X-XSS-Protection (XSS filter)
        // - Content-Security-Policy (XSS and Injection protection)
        // - Strict-Transport-Security (HTTPS enforcement)
        
        res.json({ message: 'No security headers configured' });
    };

    this.errorHandling = (req, res, next) => {
        // A10: Improper error handling
        try {
            const data = JSON.parse(req.body.jsonData);
            // Process data
        } catch (e) {
            // Vulnerable: Exposing detailed error information
            return res.json({
                error: e.message,
                stack: e.stack,
                code: e.code
            });
        }
    };

    this.debugModeEnabled = (req, res, next) => {
        // A10: Debug mode enabled in production
        const debugMode = process.env.DEBUG_MODE === 'true';
        
        if (debugMode) {
            // Vulnerable: Verbose logging and information disclosure
            console.log('Debug Mode Enabled');
            console.log('Environment Variables:', process.env);
            console.log('Request Details:', req);
        }
        
        return res.json({ debugMode });
    };
}

module.exports = LoggingHandler;
