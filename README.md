[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### About
This is a mysql pdo secure session handler with openssl encryption/decryption of session data.
Default cipher mode is AES-256-CBC. CBC mode "needs" an "encryption key" and initialisation vector for encryption/decryption.

### Features
   1. openssl encryption of session data using chosen cipher, 'general encryption key' and initialisation vector ('iv' for short)
    iv is needed because of the default cipher mode (CBC) used
   2. lifetime of a session is kept in the database (can't be tampered with that easily + leaves the calculation of
   session expiration to database (example: _DELETE FROM sessions WHERE (modified + INTERVAL lifetime SECOND) < NOW()_)

### Encryption
Encryption logic is closely related to cipher mode used (deault: AES-256-CBC) - CBC mode needs initialisation vector. If you are gonna
change the default encryption mode then the procedure could be slightly different.

We have 'encryption key' (keep this SAFE)! This can be a simple string or whatever.
Have in mind that the encryption key is first hashed using hash algorithm provided (defaults to sha256) and then applied to encryption/decryption process
together with the 'per session' generated initialisation vector (which is held in the
database).

When s session is being generated an initialisation vector for that session is also generated (you can think of it as
a 'per session' encryption key).

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



