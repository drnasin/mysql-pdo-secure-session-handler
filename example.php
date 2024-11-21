<?php
declare(strict_types=1);

/**********************************************************************************
 * Updated for PHP 8.3
 * Original created by Ante Drnasin - http://www.drnasin.com
 * Modified version includes modern PHP features and type safety
 **********************************************************************************/

include_once __DIR__ . '/vendor/autoload.php';

use Drnasin\Session\SessionHandler;

readonly class DatabaseConfig
{
    public function __construct(
        public string $host,
        public int $port,
        public string $name,
        public string $table,
        public string $username,
        public string $password,
        public string $charset,
    ) {}

    public function getDsn(): string
    {
        return sprintf(
            'mysql:host=%s;dbname=%s;port=%d;charset=%s',
            $this->host,
            $this->name,
            $this->port,
            $this->charset
        );
    }
}

class SessionManager
{
    private readonly PDO $pdo;
    private array $sessionIds = [];

    public function __construct(
        private readonly DatabaseConfig $config,
        private readonly string $encryptionKey
    ) {
        $this->initializePdo();
        $this->initializeSessionHandler();
    }

    private function initializePdo(): void
    {
        $this->pdo = new PDO(
            $this->config->getDsn(),
            $this->config->username,
            $this->config->password,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
    }

    private function initializeSessionHandler(): void
    {
        try {
            $handler = new SessionHandler(
                $this->pdo,
                $this->config->table,
                $this->encryptionKey
            );
            session_set_save_handler($handler, true);
        } catch (Exception $e) {
            error_log($e->getMessage());
            throw new RuntimeException('Failed to initialize session handler', previous: $e);
        }
    }

    public function createSessions(int $count): void
    {
        ob_start();

        for ($i = 1; $i <= $count; $i++) {
            $sessionId = session_create_id();
            session_id($sessionId);
            session_start([
                'use_strict_mode' => 1,
                'cookie_secure' => 1,
                'cookie_httponly' => 1,
                'cookie_samesite' => 'Lax'
            ]);

            $_SESSION['someKey'] = "Setting initial value of var 'someKey' in session {$sessionId}";
            session_write_close();

            $this->sessionIds[] = $sessionId;
        }

        echo "✓ Created {$count} sessions." . PHP_EOL;
    }

    public function updateSessions(): void
    {
        $updated = 0;
        foreach ($this->sessionIds as $sessionId) {
            session_id($sessionId);
            session_start();

            $_SESSION["someKey"] = "Updated value of var 'someKey' in session $sessionId";

            session_write_close();
            $updated++;
        }
        echo "✓ Updated value in {$updated}" . PHP_EOL;
    }

    public function destroySessions(): void
    {
        $destroyed = 0;
        foreach ($this->sessionIds as $sessionId) {
            session_id($sessionId);
            session_start();

            if (session_destroy()) {
                $destroyed++;
            }
        }

        echo "✓ Destroyed {$destroyed} sessions." . PHP_EOL;

        ob_end_flush();
    }
}

// Configuration
$dbConfig = new DatabaseConfig(
    host: '127.0.0.1',
    port: 3306,
    name: 'sessions',
    table: 'sessions_test',
    username: 'root',
    password: '',
    charset: 'utf8mb4'  // Updated to utf8mb4 for full Unicode support
);

$encryptionKey = trim(file_get_contents(__DIR__ . '/tests/encryption.key'));

// Usage
try {
    $sessionManager = new SessionManager($dbConfig, $encryptionKey);
    $sessionManager->createSessions(100);
    $sessionManager->updateSessions();
    $sessionManager->destroySessions();
} catch (Exception $e) {
    error_log($e->getMessage());
    die('Session management error occurred');
}