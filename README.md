[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### About
This is a mysql pdo secure session handler with **openssl encryption/decryption** of session data.

Cipher mode used for enryption/decryption is **AES-256-CBC**.

CBC has an IV and thus needs randomness every time a message is encrypted,
changing a part of the message requires re-encrypting everything after the change,
transmission errors in one ciphertext block completely destroy the plaintext and
change the decryption of the next block, decryption can be parallelized / encryption can't,
the plaintext is malleable to a certain degree.

### Features
   1. openssl encryption of session data using **AES-256-CBC** cipher, "encryption key" and initialisation vector("IV")
        - "IV" is needed because of the default cipher mode (CBC)
   2. when session is being created so is the "IV" for that session. "IV "is then stored in the database as binary data
   2. lifetime of a session is kept in the database because
        - can't be tampered with that easily
        - calculation of the sessions expiration can be left to the database (faster)
        (example: _DELETE FROM sessions WHERE (modified + INTERVAL lifetime SECOND) < NOW()_)

### Usage
Generate your encryption key using:
`openssl rand -base64 -out tests/encryption.key 180` (recommended key length is 128 - 256 bits)
then check the included example.

### Encryption
As per cipher mode used (CBC in this case) data are encrypted using:\
    - provided **encryption key** \
    - **initialisation vector (IV)** - generated for every session as a string of (pseudo)bytes, length is in colleration with\
                                       cipher mode used (AES = 256 bits = 32 bytes -> meaning: generated "IV" has to be 32 bytes long)

### Database
.sql file (mysql dialect) is provided in *schema* dir.

mysql tip: BINARY field type would also work

### Usage

`composer require drnasin/mysql-pdo-secure-session-handler`

or git clone the repo.

### Example

check `example.php`

If you need any help let me know. Just use the "Issues" tab...

### Tests
Update database variables in tests/phpunit.xml, then

run: `composer tests`

### Code coverage
Code coverage will be generated in tests/code-coverage-report directory.
