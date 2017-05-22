[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### About
This is a mysql secure session handler with AES encryption of session data.

### Features
   1. strong encryption of session data using 'session encryption key' (initialisation vector) + 'general encryption key'
   2. lifetime of a session is 'per session' base
        - this offers a great control over session (when debugging)

### Encryption
Encryption logic is as follows.

We have one GENERAL private key (keep this SAFE)! This can be a simple string, hash or even byte based.

When session is generated (written to database) an initialisation vector is generated (you can think of it as
a 'per session' encryption key). This 'session encryption key' is used WITH our general encryption key to encrypt/decrypt the data.

I'm using AES enryption for session data and sha512 for hashing the general encryption key.

### Usage

`composer require drnasin/mysql-pdo-secure-session-handler`

### Example

check `example.php`

If you need any help let me know. Just use the "Issues" tab...

### Tests
Update database variables in tests/phpunit.xml, then

run: `composer tests`

### Code coverage
Code coverage will be generated in tests/build directory.



