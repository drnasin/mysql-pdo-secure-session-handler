<?php

/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2019. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 9.7.2019 17:38                                                  *
 *                                                                                *
 * The MIT License                                                                *
 *                                                                                *
 * Permission is hereby granted, free of charge, to any person obtaining a copy   *
 * of this software and associated documentation files (the "Software"), to deal  *
 * in the Software without restriction, including without limitation the rights   *
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      *
 * copies of the Software, and to permit persons to whom the Software is          *
 * furnished to do so, subject to the following conditions:                       *
 *                                                                                *
 * The above copyright notice and this permission notice shall be included in     *
 * all copies or substantial portions of the Software.                            *
 *                                                                                *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     *
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       *
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    *
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         *
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  *
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN      *
 * THE SOFTWARE.                                                                  *
 **********************************************************************************/

namespace Drnasin\Session;

use PDO;
use Exception;
use InvalidArgumentException;
use SessionHandlerInterface;

/**
 * Class Session Save Handler.
 * Mysql (PDO) session save handler with openssl session data encryption.
 * This class encrypts the session data using the "encryption key"
 * and initialisation vector (IV) which is generated per session.
 * @package Drnasin\Session
 * @author Ante Drnasin
 * @link https://github.com/drnasin/mysql-pdo-secure-session-handler
 */
readonly class SessionHandler implements SessionHandlerInterface
{
    /**
     * Hash algorithm used
     */
    const string HASH_ALGORITHM = 'SHA256';

    /**
     * Cipher mode used for encryption/decryption
     */
    const string CIPHER_MODE = 'AES-256-CBC';

    /**
     * Length (in bytes) of IV
     */
    const int IV_LENGTH = 16;

    /**
     * Length of integrity HMAC hash
     */
    const int HASH_HMAC_LENGTH = 32;

    const string AUTH_STRING = 'Drnasin-Secure-Session-Handler';

    protected string $hashedEncryptionKey;
    protected string $authenticationKey;

    /**
     * SessionHandler constructor.
     * Make sure $encryptionKey is trimmed!
     *
     * @param PDO $pdo
     * @param string $tableName
     * @param string $encryptionKey
     * @throws Exception
     */
    public function __construct(protected PDO $pdo, protected string $tableName, protected string $encryptionKey) {
        match (true) {
            !extension_loaded('openssl') => throw new Exception('OpenSSL extension not found'),
            empty($tableName) => throw new Exception('Sessions table name is empty'),
            empty($encryptionKey) => throw new Exception('Encryption key is empty'),
            self::IV_LENGTH !== openssl_cipher_iv_length(self::CIPHER_MODE) => throw new Exception("IV length mismatch for cipher mode " . self::CIPHER_MODE),
            default => null
        };

        // initialize PDO
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
        $this->pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, false);

        // needed for encryption/decryption of plaintext data
        $this->hashedEncryptionKey = hash(self::HASH_ALGORITHM, $encryptionKey, true);

        // calculate authentication key
        $salt = hash(self::HASH_ALGORITHM, session_id() . self::AUTH_STRING, true);
        $this->authenticationKey = hash_hkdf(self::HASH_ALGORITHM, $encryptionKey, 32, self::AUTH_STRING, $salt);
    }

    public static function create(
        PDO $pdo, string $tableName, string $encryptionKey
    ): self {
        if (empty($tableName)) {
            throw new InvalidArgumentException('Table name cannot be empty');
        }

        if (empty($encryptionKey)) {
            throw new InvalidArgumentException('Encryption key cannot be empty');
        }

        return new self($pdo, $tableName, $encryptionKey);
    }

    /**
     * Workflow: Generate IV for the current session, encrypt the data using encryption key and
     * generated IV, write the session to database. Default session lifetime (usually defaults to 1440)
     * is taken directly from php.ini -> session.gc_maxlifetime.
     * @link http://php.net/manual/en/sessionhandlerinterface.write.php
     *
     * @param string $session_id The session id.
     * @param string $session_data
     * The encoded session data.
     * Please note sessions use an alternative serialization method (see php.ini)
     *
     * @return bool The return value (usually TRUE on success, FALSE on failure).
     * @throws Exception
     * @since 5.4.0
     */
    public function write(string $id, string $data): bool
    {
        try {
            $iv = random_bytes(self::IV_LENGTH);
            $encodedEncryptedData = base64_encode($this->encrypt($data, $iv));

            $stmt = $this->pdo->prepare("REPLACE INTO {$this->tableName} 
                (session_id, modified, session_data, lifetime, iv) 
                VALUES (:session_id, NOW(), :session_data, :lifetime, :iv)");

            return $stmt->execute([
                'session_id'   => $id,
                'session_data' => $encodedEncryptedData,
                'lifetime'     => ini_get('session.gc_maxlifetime'),
                'iv'           => $iv
            ]);
        } catch (Exception $e) {
            error_log("Session write error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Encrypts the data with given cipher.
     * adds HMAC checksum block of hashes to $ciphertext
     *
     * @param string $plaintext
     * @param string $iv binary initialisation vector
     *
     * @return string (raw binary data)
     *         format: rightPartOfIntegrityHmac . ciphertext . leftPartOfIntegrityHmac;
     * @throws Exception
     */
    private function encrypt(string $plaintext, string $iv): string
    {
        $authKey = $this->deriveAuthenticationKey();

        // Calculate integrity HMAC
        $integrityHmac = hash_hmac(self::HASH_ALGORITHM, $iv . $plaintext, $authKey, true);

        // Encrypt the data
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER_MODE, $this->hashedEncryptionKey, OPENSSL_RAW_DATA, $iv);

        if ($ciphertext === false) {
            throw new Exception('Encryption failed: ' . openssl_error_string());
        }

        // Split HMAC and sandwich the ciphertext
        $left = substr($integrityHmac, 0, self::HASH_HMAC_LENGTH / 2);
        $right = substr($integrityHmac, self::HASH_HMAC_LENGTH / 2);

        return $right . $ciphertext . $left;
    }

    /**
     * Derives the authentication key for the current session
     */
    private function deriveAuthenticationKey(): string
    {
        $salt = hash(self::HASH_ALGORITHM, session_id() . self::AUTH_STRING, true);

        return hash_hkdf(self::HASH_ALGORITHM, $this->encryptionKey, self::HASH_HMAC_LENGTH, self::AUTH_STRING, $salt);
    }

    /**
     * Read the session, decrypt the data with openssl cipher method, using session IV (initialisation vector)
     * and encryption key and return the decrypted data.
     * @link http://php.net/manual/en/sessionhandlerinterface.read.php
     *
     * @param string $id The session id to read data for.
     *
     * @return string|false
     * Returns an encoded string of the read data.
     * If nothing was read, it must return an empty string.
     * @since 5.4.0
     * @throws Exception
     */
    public function read(string $id): string|false
    {
        try {
            $stmt = $this->pdo->prepare("SELECT session_data, iv 
                FROM {$this->tableName} 
                WHERE session_id = :session_id 
                AND (modified + INTERVAL lifetime SECOND) > NOW()");

            if (!$stmt->execute(['session_id' => $id])) {
                return '';
            }

            $session = $stmt->fetchObject();
            if (!$session) {
                return '';
            }

            return $this->decrypt(base64_decode($session->session_data), $session->iv);
        } catch (Exception $e) {
            error_log("Session read error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Decrypts the data, extracts the header checksum,
     * re-calculates every hash and compares with data from checksum,
     * if everything goes well returns decrypted data.
     *
     * @param string $ciphertext raw string
     * @param string $iv in binary form
     *
     * @return string decrypted data
     * @throws Exception
     */
    private function decrypt(string $ciphertext, string $iv): string
    {
        if (strlen($ciphertext) < self::IV_LENGTH) {
            throw new Exception('Data integrity check failed - data too short');
        }

        // Extract HMAC parts and ciphertext
        $right = substr($ciphertext, 0, self::HASH_HMAC_LENGTH / 2);
        $left = substr($ciphertext, -(self::HASH_HMAC_LENGTH / 2));
        $ciphertext = substr($ciphertext, self::HASH_HMAC_LENGTH / 2, -(self::HASH_HMAC_LENGTH / 2));

        // Decrypt
        $plaintext = openssl_decrypt($ciphertext, self::CIPHER_MODE, $this->hashedEncryptionKey, OPENSSL_RAW_DATA, $iv);

        if ($plaintext === false) {
            throw new Exception('Decryption failed: ' . openssl_error_string());
        }

        // Verify integrity with current session's auth key
        $authKey = $this->deriveAuthenticationKey();
        $extractedHmac = $left . $right;
        $calculatedHmac = hash_hmac(self::HASH_ALGORITHM, $iv . $plaintext, $authKey, true);

        if (!hash_equals($extractedHmac, $calculatedHmac)) {
            throw new Exception('HMAC verification failed');
        }

        return $plaintext;
    }


    /**
     * Destroy a session
     * @link http://php.net/manual/en/sessionhandlerinterface.destroy.php
     *
     * @param string $session_id The session ID being destroyed.
     *
     * @return bool
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     */
    public function destroy(string $id): bool
    {
        try {
            return $this->pdo->prepare("DELETE FROM {$this->tableName} WHERE session_id = :session_id")->execute(['session_id' => $id]);
        } catch (Exception $e) {
            error_log("Session destroy error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Cleanup old sessions
     * @link http://php.net/manual/en/sessionhandlerinterface.gc.php
     *
     * @param ?int $max_lifetime
     * Sessions that have not updated for
     * the last maxlifetime seconds will be removed.
     *
     * @return bool
     *
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     */
    public function gc(?int $max_lifetime = null): int|false
    {
        try {
            return $this->pdo->prepare("DELETE FROM {$this->tableName} 
                WHERE (modified + INTERVAL lifetime SECOND) < NOW()")->execute();
        } catch (Exception $e) {
            error_log("Session GC error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Initialize session
     * @link http://php.net/manual/en/sessionhandlerinterface.open.php
     *
     * @param string $path The path where to store/retrieve the session.
     * @param string $name The session name.
     *
     * @return bool
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     * @codeCoverageIgnore
     */
    public function open(string $path, string $name): bool
    {
        return true;
    }

    /**
     * Close the session
     * @link http://php.net/manual/en/sessionhandlerinterface.close.php
     * @return bool
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     * @codeCoverageIgnore
     */
    public function close(): bool
    {
        return true;
    }

    public function createTable(): bool
    {
        $sql = "CREATE TABLE IF NOT EXISTS {$this->tableName} (
            session_id VARCHAR(128) NOT NULL PRIMARY KEY,
            modified TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            session_data MEDIUMTEXT NOT NULL,
            lifetime INT NOT NULL,
            iv VARBINARY(16) NOT NULL,
            INDEX idx_modified_lifetime (modified, lifetime)
        ) ENGINE=InnoDB";

        try {
            return $this->pdo->exec($sql) !== false;
        } catch (Exception $e) {
            error_log("Create table error: " . $e->getMessage());
            return false;
        }
    }
}
