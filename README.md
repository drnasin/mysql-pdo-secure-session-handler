[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### About
This is a mysql pdo secure session handler with openssl encryption/decryption of session data.

### Features
   1. openssl encryption of session data using openssl cipher, initialisation vector and 'general encryption key'
   2. lifetime of a session is kept in the database

### Encryption
Encryption logic is as follows.

We have one GENERAL encryption key (keep this SAFE)! This can be a simple string or whatever.
Have in mind encryption key is first hashed using hash algorithm provided and then applied to encryption/decryption process.

When session is being generated an initialisation vector for that session is also generated (you can think of it as
a 'per session' encryption key). This initialisation vector ('iv') is used WITH our hashed general encryption key to encrypt/decrypt the data.

### Usage

`composer require drnasin/mysql-pdo-secure-session-handler`

### Example

check `example.php`

If you need any help let me know. Just use the "Issues" tab...

### Tests
Update database variables in tests/phpunit.xml, then

run: `composer tests`

### Code coverage
Code coverage will be generated in tests/code-coverage-report directory.



