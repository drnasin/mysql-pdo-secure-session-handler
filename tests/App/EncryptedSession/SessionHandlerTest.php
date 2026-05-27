<?php
namespace App\EncryptedSession;

use Exception;
use InvalidArgumentException;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;

final class SessionHandlerTest extends TestCase
{
    protected PDO $pdo;
    protected EncryptedSessionHandler $handler;
    protected string $encryptionKey;

    /**
     * @throws Exception
     */
    public function setUp(): void
    {
        $dsn = sprintf($_ENV['DB_DSN'], $_ENV['DB_HOST'], $_ENV['DB_NAME'], $_ENV['DB_PORT'], $_ENV['DB_CHARSET']);
        $this->pdo = new \PDO($dsn, $_ENV['DB_USER'], $_ENV['DB_PASS']);

        $keyFilePath = __DIR__ . "/../../{$_ENV['TEST_ENCRYPTION_KEY_FILE']}";

        if (!file_exists($keyFilePath)) {
            throw new \RuntimeException("Encryption key file not found at: {$keyFilePath}");
        }

        $keyContent = file_get_contents($keyFilePath);
        if ($keyContent === false) {
            throw new \RuntimeException("Failed to read encryption key file: {$keyFilePath}");
        }

        $this->encryptionKey = trim($keyContent);
        $this->handler = EncryptedSessionHandler::create($this->pdo, $_ENV['DB_TABLENAME'], $this->encryptionKey);
        $this->handler->createTable();
    }

    /**
     * @throws Exception
     */
    #[DataProvider('sessionProvider')]
    public function testUnknownTableName(string $sessionId, string $sessionData): void
    {
        $handler = EncryptedSessionHandler::create($this->pdo, 'NonExistingTable', $this->encryptionKey);
        $this->assertFalse($handler->write($sessionId, $sessionData));
    }

    public function testConstructorUsingEmptyEncryptionKey(): void
    {
        $this->expectException(Exception::class);
        new EncryptedSessionHandler($this->pdo, $_ENV['DB_TABLENAME'], '');
    }

    #[DataProvider('invalidTableNameProvider')]
    public function testConstructorRejectsInvalidTableName(string $tableName): void
    {
        $this->expectException(InvalidArgumentException::class);
        new EncryptedSessionHandler($this->pdo, $tableName, $this->encryptionKey);
    }

    public static function invalidTableNameProvider(): array
    {
        return [
            'SQL injection'      => ['sessions; DROP TABLE users; --'],
            'spaces'             => ['my table'],
            'starts with digit'  => ['1sessions'],
            'special characters' => ['table$name'],
            'dot notation'       => ['schema.table'],
            'too long'           => [str_repeat('a', 65)],
        ];
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

    /**
     * Regression for the injected-PDO / error-handling fix: even when the
     * caller hands the handler a PDO in ERRMODE_SILENT (so failed statements
     * return false instead of throwing), every operation must fail closed
     * rather than raise an uncaught Error or report false success.
     *
     * @throws Exception
     */
    public function testFailsClosedUnderSilentErrmode(): void
    {
        $dsn = sprintf($_ENV['DB_DSN'], $_ENV['DB_HOST'], $_ENV['DB_NAME'], $_ENV['DB_PORT'], $_ENV['DB_CHARSET']);
        $silentPdo = new PDO($dsn, $_ENV['DB_USER'], $_ENV['DB_PASS'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_SILENT,
        ]);

        $handler = EncryptedSessionHandler::create($silentPdo, 'NonExistingTable', $this->encryptionKey);

        $this->assertFalse($handler->write('sid', 'data'));
        $this->assertFalse($handler->read('sid'));
        $this->assertFalse($handler->gc(0));
    }

    public function testNonExistingSessionId(): void
    {
        $nonExistingSessionId = bin2hex(openssl_random_pseudo_bytes(16));
        $this->assertEmpty($this->handler->read($nonExistingSessionId));
    }

    /**
     * The HMAC is bound to the session id, so an authenticated blob copied
     * verbatim into a different session id must fail integrity verification
     * (read returns false) rather than decrypt under the attacker's id.
     *
     * @throws Exception
     */
    public function testCrossSessionIdSubstitutionFails(): void
    {
        $table = $_ENV['DB_TABLENAME'];
        $sourceId = 'src_' . bin2hex(random_bytes(8));
        $targetId = 'tgt_' . bin2hex(random_bytes(8));
        $plaintext = 'secret payload';

        $this->assertTrue($this->handler->write($sourceId, $plaintext));
        $this->assertSame($plaintext, $this->handler->read($sourceId));

        $row = $this->pdo
            ->query(sprintf('SELECT session_data, iv FROM %s WHERE session_id = %s', $table, $this->pdo->quote($sourceId)))
            ->fetch(PDO::FETCH_ASSOC);
        $this->assertNotFalse($row);

        // Replay the source blob under a different session id.
        $stmt = $this->pdo->prepare("INSERT INTO {$table} (session_id, modified, session_data, lifetime, iv)
            VALUES (:id, NOW(), :data, :lifetime, :iv)
            ON DUPLICATE KEY UPDATE modified = NOW(), session_data = VALUES(session_data), lifetime = VALUES(lifetime), iv = VALUES(iv)");
        $stmt->execute(['id' => $targetId, 'data' => $row['session_data'], 'lifetime' => 3600, 'iv' => $row['iv']]);

        $this->assertFalse($this->handler->read($targetId));
        // The original session is untouched by the substitution attempt.
        $this->assertSame($plaintext, $this->handler->read($sourceId));

        $this->handler->destroy($sourceId);
        $this->handler->destroy($targetId);
    }

    /**
     * Stronger variant: forge a row by shifting the id/IV boundary so that,
     * under a naive (non-canonical) `id . iv . ciphertext` transcript, the
     * stored MAC would still validate under a different (shorter) session id.
     * The length-prefixed transcript must reject this. A regression to plain
     * concatenation would make read($targetId) succeed and fail this test.
     *
     * @throws Exception
     */
    public function testPrefixShiftSubstitutionFails(): void
    {
        $table = $_ENV['DB_TABLENAME'];
        $sourceId = 'src_' . bin2hex(random_bytes(8)); // 20 ASCII chars
        $plaintext = 'top secret session payload';

        $this->assertTrue($this->handler->write($sourceId, $plaintext));

        $row = $this->pdo
            ->query(sprintf('SELECT session_data, iv FROM %s WHERE session_id = %s', $table, $this->pdo->quote($sourceId)))
            ->fetch(PDO::FETCH_ASSOC);
        $this->assertNotFalse($row);

        $blob = base64_decode($row['session_data']);
        $mac = substr($blob, 0, EncryptedSessionHandler::HASH_HMAC_LENGTH);
        $ciphertext = substr($blob, EncryptedSessionHandler::HASH_HMAC_LENGTH);

        // Transcript an attacker observes for the victim row.
        $transcript = $sourceId . $row['iv'] . $ciphertext;

        // Shift the boundary left: target id = strict ASCII prefix of source id;
        // the forged IV absorbs the leftover id bytes. k is chosen so the forged
        // ciphertext stays block-aligned (k === strlen(id) mod block size) -
        // otherwise a naive implementation would fail on padding rather than on
        // the MAC, and this test would pass for the wrong reason. With aligned
        // input, a naive `id.iv.ct` MAC would validate and decrypt successfully,
        // so only the canonical (length-prefixed) transcript makes read() fail.
        $k = strlen($sourceId) % EncryptedSessionHandler::IV_LENGTH;
        $this->assertGreaterThan(0, $k, 'source id length must not be a multiple of the block size');

        $targetId  = substr($transcript, 0, $k);
        $forgedIv  = substr($transcript, $k, EncryptedSessionHandler::IV_LENGTH);
        $forgedCt  = substr($transcript, $k + EncryptedSessionHandler::IV_LENGTH);
        $forgedData = base64_encode($mac . $forgedCt);

        $this->assertNotSame($sourceId, $targetId);

        $stmt = $this->pdo->prepare("INSERT INTO {$table} (session_id, modified, session_data, lifetime, iv)
            VALUES (:id, NOW(), :data, :lifetime, :iv)
            ON DUPLICATE KEY UPDATE modified = NOW(), session_data = VALUES(session_data), lifetime = VALUES(lifetime), iv = VALUES(iv)");
        $stmt->execute(['id' => $targetId, 'data' => $forgedData, 'lifetime' => 3600, 'iv' => $forgedIv]);

        $this->assertFalse($this->handler->read($targetId));

        $this->handler->destroy($sourceId);
        $this->handler->destroy($targetId);
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