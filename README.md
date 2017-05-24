[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### About
This is a mysql pdo secure session handler with **openssl encryption/decryption** of session data.

Default cipher mode is **AES-256-CBC**.

CBC mode "needs" an "encryption key" (provided by you) and initialisation vector (generated) for encryption/decryption process.

### Features
   1. openssl encryption of session data using chosen cipher, "encryption key" and initialisation vector - "iv" for short
        - "iv" is needed because of the default cipher mode (CBC) used
   2. lifetime of a session is kept in the database
        - can't be tampered with that easily
        - calculation of sessions expiration can be left to database (example: _DELETE FROM sessions WHERE (modified + INTERVAL lifetime SECOND) < NOW()_)

### Encryption
Encryption logic is closely related to cipher mode used (deault: AES-256-CBC) - CBC mode needs initialisation vector.
If you are gonna change the default encryption mode then the procedure could be slightly different.

As per cipher mode used (CBC in this case) data are encrypted using:
    - your encryption key (which is first hash-ed using sha256, before applying)
    - initialisation vector (iv) - generated for every session (string of pseudobytes) - generated sequence length must be
    in colleration with cipher mode (AES = 128 bits = 16 bytes -> meaning: generated 'iv' has to be 16 bytes long)

When s session is being generated an initialisation vector for that session is also generated (you can think of it as
a 'per session' encryption key).

### Database
.sql file (mysql diallect) is provided.

mysql tip: BINARY field type would also work

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



