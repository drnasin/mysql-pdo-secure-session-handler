[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### About
This is a mysql pdo secure session handler with **openssl encryption/decryption** of session data.

Default cipher mode is **AES-256-CBC**.

CBC mode "needs":
    - an "encryption key" and\
    - initialisation vector ("iv") (generated string of pseudobytes in binary format) for encryption/decryption process.

### Features
   1. openssl encryption of session data using chosen cipher, "encryption key" and initialisation vector("iv")
        - "iv" is needed because of the default cipher mode (CBC)
   2. when session is being created so is the "iv" for that session. "iv "is then stored in the database as binary data
   2. lifetime of a session is kept in the database because
        - can't be tampered with that easily
        - calculation of the sessions expiration can be left to the database (faster)\
        (example: _DELETE FROM sessions WHERE (modified + INTERVAL lifetime SECOND) < NOW()_)

### Usage
Generate your encryption key using:\
`openssl rand -base64 -out storage/enc.key 180`
then check the included example.

### Encryption
As per cipher mode used (CBC in this case) data are encrypted using:\
    - provided **encryption key** (which is first hash-ed using sha256, before applying) \
    - **initialisation vector (iv)** - generated for every session as a string of (pseudo)bytes, length is in colleration with\
                                       cipher mode used (AES = 128 bits = 16 bytes -> meaning: generated "iv" has to be 16 bytes long)

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



