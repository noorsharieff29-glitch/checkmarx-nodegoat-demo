/**
 * Input validation and business logic vulnerabilities
 * A1: Injection
 * A3: XSS
 * A5: Broken Access Control
 * A7: XXE
 */

function ValidationHandler(db) {
    'use strict';

    this.crossSiteScripting = (req, res, next) => {
        // A3: Cross-Site Scripting (XSS)
        const userComment = req.body.comment;
        const userName = req.body.name;
        
        // Vulnerable: Directly rendering user input without sanitization
        const html = `
            <div class="comment">
                <strong>${userName}</strong> wrote:
                <p>${userComment}</p>
            </div>
        `;
        
        return res.render('comment', { html, content: html });
    };

    this.reflectedXSS = (req, res, next) => {
        // A3: Reflected XSS
        const searchQuery = req.query.q;
        
        // Vulnerable: Unsanitized query reflected in response
        return res.render('search', {
            message: `You searched for: ${searchQuery}`
        });
    };

    this.storedXSS = (req, res, next) => {
        // A3: Stored XSS
        const postContent = req.body.content;
        const postTitle = req.body.title;
        
        // Vulnerable: Storing unsanitized user input
        db.collection('posts').insertOne({
            title: postTitle,
            content: postContent,
            author: req.session.userId,
            createdAt: new Date()
        }, (err, result) => {
            if (err) return next(err);
            
            // Vulnerable: Rendering stored XSS without escaping
            return res.render('post', {
                title: postContent,
                body: postContent
            });
        });
    };

    this.typeConfusion = (req, res, next) => {
        // A5: Type confusion / Broken access control
        const role = req.body.role;
        const isAdmin = (role == 'admin');  // Vulnerable: Using == instead of ===
        
        // An attacker could pass role as an array or object to bypass this check
        if (isAdmin) {
            return res.json({ admin: true });
        }
        return res.json({ admin: false });
    };

    this.prototypePolluion = (req, res, next) => {
        // A5: Prototype Pollution
        const userData = req.body;
        const user = {};
        
        // Vulnerable: Using Object.assign with untrusted data
        Object.assign(user, userData);
        
        // Attacker can pollute Object.prototype by sending:
        // { "__proto__": { "isAdmin": true } }
        // or { "constructor": { "prototype": { "isAdmin": true } } }
        
        return res.json({ user });
    };

    this.insufficientInputValidation = (req, res, next) => {
        // A1: Injection - Insufficient input validation
        const age = req.body.age;
        const email = req.body.email;
        const url = req.body.url;
        
        // Vulnerable: Minimal validation
        if (age > 0) {  // Only checks if positive
            // But could be negative number or string like "999999999"
        }
        
        if (email.includes('@')) {  // Only checks for @
            // Doesn't validate proper email format
        }
        
        // Vulnerable: No validation of URL
        db.collection('users').insertOne({
            age: parseInt(age),
            email: email,
            website: url  // Could be javascript:alert('xss') or data:
        }, (err, result) => {
            if (err) return next(err);
            return res.json({ success: true });
        });
    };

    this.ldapInjection = (req, res, next) => {
        // A1: LDAP Injection
        const username = req.body.username;
        
        // Vulnerable: Direct concatenation in LDAP filter
        const ldapFilter = `(&(uid=${username})(objectClass=posixAccount))`;
        
        // Attacker could inject: *)(uid=*))(&(uid=*
        // This would create: (&(uid=*)(uid=*))(&(uid=*)(objectClass=posixAccount))
        // Resulting in always-true condition
        
        return res.json({ filter: ldapFilter });
    };

    this.businessLogicBypass = (req, res, next) => {
        // A7: Business Logic Bypass
        const amount = req.body.amount;
        const discount = req.body.discount;
        
        // Vulnerable: Allows negative amounts or unreasonable discounts
        let finalPrice = amount * (1 - discount / 100);
        
        // Attacker could send:
        // amount: -1000, discount: 100
        // Result: -1000 * 0 = 0 or even positive profit to attacker
        
        if (finalPrice < 0) {
            finalPrice = 0;  // Insufficient fix
        }
        
        return res.json({ finalPrice });
    };

    this.racCondition = (req, res, next) => {
        // A7: Race Condition
        const userId = req.session.userId;
        const transferAmount = req.body.amount;
        
        // Vulnerable: TOCTOU (Time Of Check, Time Of Use) race condition
        db.collection('accounts').findOne({ userId: userId }, (err, account) => {
            if (err) return next(err);
            
            if (account.balance >= transferAmount) {
                // Vulnerable: Multiple operations without atomicity
                // Between this check and the update, another request could spend the balance
                
                setTimeout(() => {  // Simulating delay
                    db.collection('accounts').updateOne(
                        { userId: userId },
                        { $inc: { balance: -transferAmount } },
                        (err, result) => {
                            if (err) return next(err);
                            return res.json({ success: true });
                        }
                    );
                }, 100);
            }
        });
    };
}

module.exports = ValidationHandler;
