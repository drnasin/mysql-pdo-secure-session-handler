<?php
namespace Drnasin\Session;

use Exception;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use PDO;

final class SessionHandlerTest extends TestCase
{
    protected PDO $pdo;
    protected SessionHandler $handler;
    protected string $encryptionKey;

    /**
     * @throws Exception
     */
    public function setUp(): void
    {
        $dsn = sprintf($_ENV['DB_DSN'], $_ENV['DB_HOST'], $_ENV['DB_NAME'], $_ENV['DB_PORT'], $_ENV['DB_CHARSET']);
        $this->pdo = new \PDO($dsn, $_ENV['DB_USER'], $_ENV['DB_PASS']);

        $keyFilePath = __DIR__ . "/../../../{$_ENV['TEST_ENCRYPTION_KEY_FILE']}";

        if (!file_exists($keyFilePath)) {
            throw new \RuntimeException("Encryption key file not found at: {$keyFilePath}");
        }

        $keyContent = file_get_contents($keyFilePath);
        if ($keyContent === false) {
            throw new \RuntimeException("Failed to read encryption key file: {$keyFilePath}");
        }

        $this->encryptionKey = trim($keyContent);
        $this->handler = SessionHandler::create($this->pdo, $_ENV['DB_TABLENAME'], $this->encryptionKey);
        $this->handler->createTable();
    }

    /**
     * @throws Exception
     */
    #[DataProvider('sessionProvider')]
    public function testUnknownTableName(string $sessionId, string $sessionData): void
    {
        $handler = SessionHandler::create($this->pdo, 'NonExistingTable', $this->encryptionKey);
        $this->assertFalse($handler->write($sessionId, $sessionData));
    }

    public function testConstructorUsingEmptyEncryptionKey(): void
    {
        $this->expectException(Exception::class);
        new SessionHandler($this->pdo, $_ENV['DB_TABLENAME'], '');
    }

    /**
     * @throws Exception
     */
    #[DataProvider('sessionProvider')]
    public function testSessionWrite(string $sessionId, string $sessionData): void
    {
        $this->assertTrue($this->handler->write($sessionId, $sessionData));
    }

    #[DataProvider('sessionProvider')]
    #[Depends('testSessionWrite')]
    public function testSessionRead(string $sessionId, string $sessionData): void
    {
        $this->assertEquals($sessionData, $this->handler->read($sessionId));
    }

    #[DataProvider('sessionProvider')]
    #[Depends('testSessionRead')]
    public function testSessionDestroy(string $sessionId, string $sessionData): void
    {
        $this->assertTrue($this->handler->destroy($sessionId));
    }

    public function testSessionGarbageCollector(): void
    {
        $this->assertIsInt($this->handler->gc(0));
    }

    public function testNonExistingSessionId(): void
    {
        $nonExistingSessionId = bin2hex(openssl_random_pseudo_bytes(16));
        $this->assertEmpty($this->handler->read($nonExistingSessionId));
    }

    public static function sessionProvider(): array
    {
        $sessionId = md5(__NAMESPACE__);
        $sessionData = 'Lorem ipsum dolor sit amet';

        return [
            [$sessionId, $sessionData]
        ];
    }
}