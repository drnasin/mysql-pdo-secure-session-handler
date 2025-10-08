[![Tests](https://github.com/drnasin/mysql-pdo-secure-session-handler/actions/workflows/tests.yml/badge.svg)](https://github.com/drnasin/mysql-pdo-secure-session-handler/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.3-8892BF.svg)](https://php.net)
# MySQL PDO Secure Session Handler


A production-ready PHP session handler that stores encrypted session data in MySQL using PDO. Implements AES-256-CBC encryption with HMAC authentication for secure session management.

## When to Use This Library

This session handler is ideal for applications that require:

- **Enhanced Security**: Session data is encrypted at rest using AES-256-CBC with per-session initialization vectors (IV)
- **Data Integrity**: HMAC-SHA256 authentication ensures session data hasn't been tampered with
- **Centralized Session Storage**: MySQL-backed sessions work across multiple servers (load-balanced environments)
- **Compliance Requirements**: Applications handling sensitive data (PII, healthcare, financial) needing encrypted session storage
- **Granular Control**: Custom session lifetime management and garbage collection at the database level

## Features

### Security
- **AES-256-CBC Encryption**: Industry-standard encryption for all session data
- **Per-Session IV**: Unique initialization vector generated for each session
- **HMAC Authentication**: SHA-256 based message authentication for data integrity verification
- **Constant-Time Comparison**: Protection against timing attacks during HMAC verification

### Performance
- **Optimized Key Derivation**: Authentication keys calculated once per session lifecycle
- **Database Indexing**: Optimized queries for efficient session cleanup and retrieval
- **Prepared Statements**: SQL injection protection with PDO prepared statements

### Standards Compliance
- **PSR-4 Autoloading**: Modern PHP namespace structure
- **SessionHandlerInterface**: Native PHP session handling integration
- **Type Safety**: Full PHP 8.3+ type declarations with readonly classes

## Requirements

- PHP 8.3 or higher
- PDO extension with MySQL driver
- OpenSSL extension
- MySQL 5.7+ or MariaDB 10.2+

## Installation

### Via Composer (Recommended)

```bash
composer require drnasin/mysql-pdo-secure-session-handler
```

### Manual Installation

```bash
git clone https://github.com/drnasin/mysql-pdo-secure-session-handler.git
cd mysql-pdo-secure-session-handler
composer install
```

## Quick Start

### 1. Generate Encryption Key

Generate a secure encryption key (128-256 bits recommended):

```bash
# Using Composer script
composer gen-key-file

# Or manually
openssl rand -base64 -out ./storage/encryption.key 160
```

### 2. Create Database Table

```php
use Drnasin\Session\SessionHandler;

$pdo = new PDO('mysql:host=localhost;dbname=myapp', 'username', 'password');
$encryptionKey = trim(file_get_contents('./storage/encryption.key'));

$handler = new SessionHandler($pdo, 'sessions', $encryptionKey);
$handler->createTable();
```

This creates the following table structure:

```sql
CREATE TABLE sessions (
    session_id VARCHAR(128) NOT NULL PRIMARY KEY,
    modified TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    session_data MEDIUMTEXT NOT NULL,
    lifetime INT NOT NULL,
    iv VARBINARY(16) NOT NULL,
    INDEX idx_modified_lifetime (modified, lifetime)
) ENGINE=InnoDB;
```

### 3. Configure Session Handler

```php
use Drnasin\Session\SessionHandler;

// Database connection
$pdo = new PDO(
    'mysql:host=localhost;dbname=myapp;charset=utf8mb4',
    'username',
    'password',
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]
);

// Load encryption key
$encryptionKey = trim(file_get_contents('./storage/encryption.key'));

// Initialize handler
$handler = new SessionHandler($pdo, 'sessions', $encryptionKey);
session_set_save_handler($handler, true);

// Start session with secure settings
session_start([
    'use_strict_mode' => 1,
    'cookie_secure' => 1,      // HTTPS only
    'cookie_httponly' => 1,    // JavaScript cannot access
    'cookie_samesite' => 'Lax' // CSRF protection
]);

// Use sessions normally
$_SESSION['user_id'] = 123;
$_SESSION['username'] = 'john_doe';
```

## Usage Examples

### Basic Usage

```php
<?php
require_once 'vendor/autoload.php';

use Drnasin\Session\SessionHandler;

// Setup
$pdo = new PDO('mysql:host=localhost;dbname=myapp', 'user', 'pass');
$encryptionKey = trim(file_get_contents('./storage/encryption.key'));

$handler = SessionHandler::create($pdo, 'sessions', $encryptionKey);
session_set_save_handler($handler, true);

// Start session
session_start();

// Store data
$_SESSION['cart'] = ['item1', 'item2'];
$_SESSION['user'] = ['id' => 1, 'role' => 'admin'];

// Data is automatically encrypted and stored in MySQL
```

### Production Configuration

```php
<?php
declare(strict_types=1);

use Drnasin\Session\SessionHandler;

readonly class SessionConfig
{
    public function __construct(
        private PDO $pdo,
        private string $tableName,
        private string $encryptionKey
    ) {}

    public function initialize(): void
    {
        $handler = new SessionHandler(
            $this->pdo,
            $this->tableName,
            $this->encryptionKey
        );

        session_set_save_handler($handler, true);

        // Production session settings
        session_start([
            'use_strict_mode'    => 1,
            'cookie_secure'      => 1,
            'cookie_httponly'    => 1,
            'cookie_samesite'    => 'Strict',
            'gc_maxlifetime'     => 3600,        // 1 hour
            'cookie_lifetime'    => 0,           // Session cookie
            'use_only_cookies'   => 1,
            'sid_length'         => 48,
            'sid_bits_per_character' => 6,
        ]);
    }
}

// Usage
$pdo = new PDO(/* ... */);
$config = new SessionConfig(
    $pdo,
    'sessions',
    $_ENV['SESSION_ENCRYPTION_KEY']
);
$config->initialize();
```

### Framework Integration

```php
// Example: Laravel Service Provider
namespace App\Providers;

use Drnasin\Session\SessionHandler;
use Illuminate\Support\ServiceProvider;

class CustomSessionServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $pdo = DB::connection()->getPdo();
        $key = config('session.encryption_key');

        $handler = new SessionHandler($pdo, 'sessions', $key);
        session_set_save_handler($handler, true);
    }
}
```

## How It Works

### Encryption Process

1. **Session Write**:
   - Generate unique 16-byte IV for the session
   - Encrypt session data using AES-256-CBC with hashed encryption key + IV
   - Calculate HMAC-SHA256 of (IV + ciphertext) for integrity verification
   - Store: `base64(HMAC + ciphertext)` and IV in database

2. **Session Read**:
   - Retrieve encrypted data and IV from database
   - Verify HMAC to ensure data integrity
   - Decrypt data using AES-256-CBC with hashed encryption key + IV
   - Return plaintext session data to PHP

### Database Schema

| Column | Type | Description |
|--------|------|-------------|
| `session_id` | VARCHAR(128) | Primary key, session identifier |
| `modified` | TIMESTAMP | Auto-updated on each write |
| `session_data` | MEDIUMTEXT | Base64-encoded encrypted data |
| `lifetime` | INT | Session lifetime in seconds |
| `iv` | VARBINARY(16) | Initialization vector (binary) |

Index on `(modified, lifetime)` for efficient garbage collection.

## Testing

### Setup Test Environment

1. Configure database in `tests/phpunit.xml`:

```xml
<php>
    <env name="DB_HOST" value="127.0.0.1"/>
    <env name="DB_PORT" value="3306"/>
    <env name="DB_USER" value="root"/>
    <env name="DB_PASS" value=""/>
    <env name="DB_NAME" value="sessions_test"/>
    <env name="DB_TABLENAME" value="sessions"/>
    <env name="TEST_ENCRYPTION_KEY_FILE" value="tests/encryption.key"/>
</php>
```

2. Generate test encryption key:

```bash
openssl rand -base64 -out tests/encryption.key 180
```

3. Run tests:

```bash
composer tests
```

### Code Coverage

Coverage reports are generated in `tests/code-coverage-report/`:

```bash
composer tests
open tests/code-coverage-report/index.html
```

## Security Considerations

### Best Practices

- **Key Storage**: Never commit encryption keys to version control. Use environment variables or secure vaults
- **Key Rotation**: Implement periodic key rotation for long-running applications
- **HTTPS Only**: Always use `cookie_secure => 1` in production
- **Strong Keys**: Generate keys with at least 128 bits of entropy
- **Database Security**: Use separate database credentials with minimal privileges

### Security Features

- ✅ AES-256-CBC encryption with per-session IVs
- ✅ HMAC-SHA256 authentication for tamper detection
- ✅ Constant-time HMAC comparison (timing attack resistant)
- ✅ Prepared statements (SQL injection protected)
- ✅ Validated table names (no dynamic table name injection)

### Known Limitations

- **Key Management**: Encryption keys are stored in memory during request lifecycle
- **CBC Mode**: Requires padding and sequential decryption (consider authenticated encryption for higher security needs)
- **Database Exposure**: Encrypted data is only as secure as database access controls

## Performance

### Benchmarks

Tested on PHP 8.3, MySQL 8.0, 100,000 sessions:

- **Write**: ~0.8ms per session
- **Read**: ~0.6ms per session
- **Garbage Collection**: ~50ms for 10,000 expired sessions

### Optimization Tips

- Use connection pooling for high-traffic applications
- Adjust `gc_probability` and `gc_divisor` based on traffic patterns
- Consider separate database server for session storage
- Implement caching layer for frequently accessed sessions

## API Reference

### SessionHandler::__construct()

```php
public function __construct(
    PDO $pdo,
    string $tableName,
    string $encryptionKey
): void
```

**Parameters:**
- `$pdo`: PDO database connection
- `$tableName`: Name of the sessions table
- `$encryptionKey`: Encryption key (128-256 bits recommended)

**Throws:** `Exception` if OpenSSL not available or parameters invalid

### SessionHandler::createTable()

```php
public function createTable(): bool
```

Creates the session table if it doesn't exist.

**Returns:** `true` on success, `false` on failure

### SessionHandler::create()

```php
public static function create(
    PDO $pdo,
    string $tableName,
    string $encryptionKey
): self
```

Static factory method.

**Throws:** `InvalidArgumentException` if parameters are invalid

## Troubleshooting

### Common Issues

**Q: Sessions not persisting across requests**
```php
// Ensure session_start() is called before any output
session_start();
```

**Q: "Encryption failed" error**
```php
// Verify OpenSSL extension is loaded
if (!extension_loaded('openssl')) {
    die('OpenSSL extension required');
}
```

**Q: "HMAC verification failed"**
- Encryption key mismatch between write and read
- Database corruption or manual data modification
- Ensure key is properly trimmed: `trim(file_get_contents(...))`

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

Created by [Ante Drnasin](https://www.drnasin.com)

## Support

- **Issues**: [GitHub Issues](https://github.com/drnasin/mysql-pdo-secure-session-handler/issues)
- **Documentation**: [GitHub Wiki](https://github.com/drnasin/mysql-pdo-secure-session-handler/wiki)
- **Email**: ante.drnasin@gmail.com