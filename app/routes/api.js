const express = require('express');
const os = require('os');
const child_process = require('child_process');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3');
const MongoClient = require('mongodb').MongoClient;

/**
 * API Routes with multiple OWASP Top 10 vulnerabilities
 * A2: Authentication Bypass
 * A3: Injection (Command, SQL, NoSQL)
 * A4: Broken Access Control
 * A6: Sensitive Data Exposure
 * A9: Components with Known Vulnerabilities
 */

function APIHandler(db) {
    'use strict';

    this.handleFileUpload = (req, res, next) => {
        // A4: Broken Access Control - No proper authorization check
        const uploadDir = path.join(__dirname, '../uploads');
        const filename = req.body.filename;
        
        // A6: Insecure file handling - allows path traversal
        const filepath = path.join(uploadDir, filename);
        const fileContent = req.body.content;
        
        // Vulnerable: No validation of file path - path traversal attack
        fs.writeFileSync(filepath, fileContent);
        res.json({ success: true, path: filepath });
    };

    this.executeCommand = (req, res, next) => {
        // A3: OS Command Injection - Direct use of user input in command execution
        const userInput = req.body.command;
        const systemCommand = `ping -c 4 ${userInput}`;
        
        // Vulnerable: No sanitization of userInput
        child_process.exec(systemCommand, (error, stdout, stderr) => {
            if (error) {
                return res.json({ error: error.message });
            }
            return res.json({ output: stdout });
        });
    };

    this.sqlInjection = (req, res, next) => {
        // A3: SQL Injection
        const username = req.body.username;
        const password = req.body.password;
        
        // Vulnerable: Direct string concatenation in SQL query
        const query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        
        // Execute against SQLite for demo
        const sqliteDb = new sqlite3.Database(':memory:');
        sqliteDb.get(query, (err, row) => {
            if (err) {
                return res.json({ error: err.message });
            }
            return res.json({ user: row });
        });
    };

    this.noSqlInjection = (req, res, next) => {
        // A3: NoSQL Injection
        const userId = req.body.userId;
        
        // Vulnerable: User input directly used in query object
        const query = { $where: `this._id == ${userId}` };
        
        db.collection('users').findOne(query, (err, user) => {
            if (err) return next(err);
            return res.json({ user });
        });
    };

    this.brokenAuthentication = (req, res, next) => {
        // A2: Broken Authentication
        const username = req.body.username;
        const password = req.body.password;
        
        // Vulnerable: Hardcoded credentials
        if (username === 'admin' && password === 'password123') {
            req.session.userId = 'admin';
            return res.json({ success: true, message: 'Login successful' });
        }
        
        // Vulnerable: No rate limiting - allows brute force attacks
        return res.json({ success: false, message: 'Invalid credentials' });
    };

    this.sensitiveDataExposure = (req, res, next) => {
        // A6: Sensitive Data Exposure
        const userId = req.body.userId;
        
        // Vulnerable: Returning sensitive data in logs
        console.log(`User ${userId} requesting sensitive data`);
        
        db.collection('users').findOne({ _id: userId }, (err, user) => {
            if (err) return next(err);
            
            // Vulnerable: Exposing sensitive fields like SSN, credit card without encryption
            // Vulnerable: No HTTPS enforced (see server.js for HTTP-only config)
            return res.json({
                userId: user._id,
                name: user.name,
                ssn: user.ssn,  // Sensitive
                creditCard: user.creditCard,  // Sensitive
                bankRouting: user.bankRouting  // Sensitive
            });
        });
    };

    this.xxeVulnerability = (req, res, next) => {
        // A4: XML External Entity (XXE) Attack
        const xml2js = require('xml2js');
        const xmlData = req.body.xmlData;
        
        const parser = new xml2js.Parser({
            // Vulnerable: XXE not disabled
            strict: false
        });
        
        parser.parseString(xmlData, (err, result) => {
            if (err) return next(err);
            return res.json({ data: result });
        });
    };

    this.brokenAccessControl = (req, res, next) => {
        // A4: Broken Access Control - IDOR (Insecure Direct Object Reference)
        const userId = req.params.userId;  // From URL parameter
        
        // Vulnerable: No check if current user has permission to access this userId
        db.collection('users').findOne({ _id: userId }, (err, user) => {
            if (err) return next(err);
            // Any authenticated user can access any other user's data
            return res.json(user);
        });
    };

    this.deserialization = (req, res, next) => {
        // A8: Insecure Deserialization
        const nodeSerialize = require('node-serialize');
        const data = req.body.serializedData;
        
        // Vulnerable: Unsafe deserialization of untrusted data
        const unserializedData = nodeSerialize.unserialize(data);
        return res.json({ data: unserializedData });
    };

    this.insecureDependencies = (req, res, next) => {
        // A9: Using Components with Known Vulnerabilities
        // Note: Some old/vulnerable versions in package.json
        // Examples:
        // - Using old version of express with known vulnerabilities
        // - Using outdated mongodb driver
        // - Using deprecated sanitization libraries
        
        const marked = require('marked');
        const userContent = req.body.content;
        
        // Vulnerable: Old version of marked with XSS vulnerabilities
        const html = marked(userContent);
        return res.json({ html });
    };

    this.informationDisclosure = (req, res, next) => {
        // A10: Security Misconfiguration - Information Disclosure
        const stack = new Error().stack;
        
        // Vulnerable: Exposing stack traces and system information
        return res.json({
            message: 'An error occurred',
            stack: stack,  // Stack trace exposed
            nodeVersion: process.version,  // System info
            platform: process.platform,  // System info
            env: process.env  // Potentially exposes secrets
        });
    };
}

module.exports = APIHandler;
