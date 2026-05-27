# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a PHP library providing a secure MySQL PDO session handler with OpenSSL encryption. The library encrypts session data using AES-256-CBC cipher with per-session initialization vectors (IV) and HMAC authentication. As of 2.0.0 the HMAC is bound to the session id, so an encrypted blob cannot be replayed under a different session id (this invalidates sessions stored by 1.x on upgrade).

## Development Commands

### Testing
- Run all tests: `composer tests` (equivalent to `phpunit -c tests/phpunit.xml`)
- Tests are split into unit tests (`SessionHandlerTest.php`) and functional tests (`SessionsTest.php`)
- Tests require database configuration in `tests/phpunit.xml` environment variables

### Key Generation
- Generate encryption key: `composer gen-key-file` (creates 160-byte base64 key in `./storage/enc.key`)
- Manual key generation: `openssl rand -base64 -out tests/encryption.key 180`

## Architecture

### Core Components

**EncryptedSessionHandler** (`src/App/EncryptedSession/EncryptedSessionHandler.php`)
- Implements `SessionHandlerInterface` with readonly class design
- Uses AES-256-CBC encryption with 16-byte IV per session
- HMAC-SHA256 authentication for data integrity
- Handles database operations via PDO with proper prepared statements

### Security Implementation

**Encryption Flow:**
1. Generate random 16-byte IV per session
2. Encrypt session data with AES-256-CBC using hashed encryption key + IV
3. Calculate HMAC-SHA256 over a canonical, length-prefixed transcript of the session id, IV and ciphertext: `pack('N', strlen($id)) . $id . $iv . $ciphertext` (Encrypt-then-MAC, verified before decryption). The length prefix removes the id/IV boundary ambiguity so a boundary-shifted id cannot validate the same tag.
4. Store: base64(HMAC + ciphertext) in `session_data`, raw IV in `iv`

**Key Derivation:**
- Encryption key: SHA256 hash of provided key
- Authentication key: HKDF-SHA256 with fixed info string

**Behavioral notes:**
- The injected PDO is used as-is (its attributes are not modified). All public methods catch `\Throwable` and fail closed (return false / empty), so the handler is safe under any PDO error mode; `ERRMODE_EXCEPTION` (PHP 8.0+ default) is recommended.
- `write()` upserts via `INSERT ... ON DUPLICATE KEY UPDATE` (not `REPLACE INTO`).
- `gc()` intentionally ignores its `$max_lifetime` argument: expiry is governed by the per-session `lifetime` column stored at write time.
- Empty table name / encryption key throw `InvalidArgumentException`; invalid table names are rejected by a regex + length check before being interpolated into SQL.

### Database Schema

Table structure (via `createTable()` method):
```sql
CREATE TABLE sessions_table (
    session_id VARCHAR(128) PRIMARY KEY,
    modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    session_data MEDIUMTEXT NOT NULL,
    lifetime INT NOT NULL,
    iv VARBINARY(16) NOT NULL,
    INDEX idx_modified_lifetime (modified, lifetime)
)
```

### Configuration Requirements

**Environment Variables (for tests):**
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME`, `DB_TABLENAME`
- `TEST_ENCRYPTION_KEY_FILE` - path to encryption key file

**Dependencies:**
- PHP 8.3+
- ext-openssl, ext-pdo
- MySQL database

## Code Patterns

- Modern PHP 8.3 features: readonly classes, match expressions, constructor property promotion
- Strict type declarations throughout
- Exception handling with proper error logging
- Uses PSR-4 autoloading (`App\` namespace maps to `src/App`)
- Test setup uses environment variables from phpunit.xml

## Key Files

- `src/App/EncryptedSession/EncryptedSessionHandler.php` - Main session handler implementation
- `example.php` - Complete usage example with modern SessionManager wrapper
- `tests/phpunit.xml` - Test configuration with database connection settings
- `composer.json` - Dependencies and scripts configuration