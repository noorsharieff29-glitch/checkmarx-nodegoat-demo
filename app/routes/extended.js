const path = require('path');
const fs = require('fs');
const tar = require('tar');
const yaml = require('js-yaml');

/**
 * Additional OWASP Top 10 and other security vulnerabilities
 * A1: Injection attacks (various types)
 * A5: Broken access control
 * A7: Path traversal
 * A9: Insecure file operations
 */

function ExtendedHandler(db) {
    'use strict';

    this.zipSlip = (req, res, next) => {
        // A7: Zip Slip vulnerability - Directory traversal via archive extraction
        const archivePath = req.body.archivePath;
        const extractPath = path.join(__dirname, '../extracts');
        
        // Vulnerable: No validation of extracted file paths
        // An attacker could create a zip with files like: "../../etc/passwd"
        tar.extract({
            file: archivePath,
            cwd: extractPath
            // Missing: stripComponents or validation
        }, (err) => {
            if (err) return next(err);
            return res.json({ success: true });
        });
    };

    this.yamlInjection = (req, res, next) => {
        // A1: YAML Injection / Deserialization
        const yamlData = req.body.yaml;
        
        // Vulnerable: Using js-yaml with unsafe options
        try {
            const data = yaml.load(yamlData);
            // YAML can execute arbitrary JavaScript if not configured safely
            return res.json({ data });
        } catch (e) {
            return res.json({ error: e.message });
        }
    };

    this.templateInjection = (req, res, next) => {
        // A1: Template Injection (SSTI)
        const userTemplate = req.body.template;
        const swig = require('swig');
        
        // Vulnerable: Using user input as template
        // Attacker could inject: {{ process.mainModule.require('child_process').execSync('id') }}
        const compiledTemplate = swig.compile(userTemplate);
        const output = compiledTemplate({ user: req.session.user });
        
        return res.json({ output });
    };

    this.httpParameterPollution = (req, res, next) => {
        // A7: HTTP Parameter Pollution
        const amount = req.query.amount;  // Can be called multiple times
        
        // Vulnerable: Not handling multiple parameters properly
        // req.query.amount could be: array, string, or multiple values
        // Different backends might interpret this differently
        
        const numAmount = parseInt(amount);
        return res.json({ amount: numAmount });
    };

    this.openRedirect = (req, res, next) => {
        // A7: Open Redirect
        const redirectUrl = req.query.redirect;
        
        // Vulnerable: No validation of redirect URL
        // Attacker could redirect to: http://evil.com/malware
        res.redirect(redirectUrl);
    };

    this.crlf Injection = (req, res, next) => {
        // A1: CRLF Injection
        const headerValue = req.body.headerValue;
        const userAgent = req.get('user-agent');
        
        // Vulnerable: User input in response header without validation
        // Attacker could inject: "test\r\nSet-Cookie: admin=true"
        res.setHeader('X-Custom-Header', headerValue);
        res.setHeader('X-User-Agent', userAgent);
        
        return res.json({ success: true });
    };

    this.dotFileAccess = (req, res, next) => {
        // A5: Broken access control - accessing sensitive files
        const filename = req.query.file;
        
        // Vulnerable: No prevention of accessing dot files
        // Attacker could request: .env, .git/config, .aws/credentials
        const filepath = path.join(__dirname, '../files', filename);
        
        fs.readFile(filepath, 'utf8', (err, data) => {
            if (err) return next(err);
            return res.json({ content: data });
        });
    };

    this.environmentVariableExposure = (req, res, next) => {
        // A6: Sensitive Data Exposure - Environment variables
        
        // Vulnerable: Exposing environment variables in responses or logs
        console.log('Database URL:', process.env.MONGODB_URI);
        console.log('API Key:', process.env.API_KEY);
        console.log('Secret:', process.env.SECRET);
        
        return res.json({
            environment: process.env,  // Exposes ALL env vars
            dbUrl: process.env.MONGODB_URI,
            apiKey: process.env.API_KEY
        });
    };

    this.insecureFileDownload = (req, res, next) => {
        // A5: Broken access control - Arbitrary file download
        const fileId = req.query.id;
        
        // Vulnerable: No validation or authorization check
        const filepath = path.join(__dirname, `../files/${fileId}`);
        
        // Could allow: ../../../etc/passwd
        res.download(filepath);
    };

    this.uncheckedRedirect = (req, res, next) => {
        // A7: Open Redirect via referrer header
        const referer = req.get('referer');
        
        // Vulnerable: Trusting user-controlled headers
        if (referer) {
            res.redirect(referer);
        } else {
            res.redirect('/home');
        }
    };
}

module.exports = ExtendedHandler;
