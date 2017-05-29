<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 29.5.2017 19:19                                                 *
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

/**
 * Class Session Save Handler.
 * Mysql (PDO) session save handler with openssl session data encryption.
 * This class encrypts the session data using the "encryption key"
 * and initialisation vector (IV) which is generated per session.
 * @package Drnasin\Session
 * @author Ante Drnasin
 * @link https://github.com/drnasin/mysql-pdo-secure-session-handler
 */
class SessionHandler implements \SessionHandlerInterface
{
    /**
     * Hash algorithm used
     * @var string
     */
    const HASH_ALGORITHM = 'SHA256';
    /**
     * Cipher mode used for encryption/decryption
     * @var string
     */
    const CIPHER_MODE = 'AES-256-CBC';
    /**
     * Length (in bytes) of iv
     * @var int
     */
    const IV_LENGTH = 16;
    /**
     * Length of one header block
     * @var int
     */
    const HMAC_HASH_LENGTH = 32;
    /**
     * Length of one header block
     * @var int
     */
    const IV_HMAC_LENGTH = 32;
    /**
     *
     */
    const AUTH_BLOCK_LENGTH = 3;
    /**
     * Database connection.
     * @var \PDO
     */
    protected $pdo;
    /**
     * Name of the DB table which holds the sessions.
     * @var string
     */
    protected $sessionsTableName;
    /**
     * 'Encryption key'.
     * Used in combination with session's initialisation vector (IV) to encrypt/decrypt the session data.
     * Keep it SAFE and PRIVATE!
     * @important encryption key is hashed using $hashAlgorithm before enryption/decryption
     * @var string
     */
    protected $encryptionKey;

    /**
     * SessionHandler constructor.
     * Make sure $encryptionKey is trimmed!
     *
     * @param \PDO   $pdo
     * @param string $sessionsTableName
     * @param string $encryptionKey
     *
     * @throws \Exception
     */
    public function __construct(\PDO $pdo, $sessionsTableName, $encryptionKey)
    {
        if (!extension_loaded('openssl')) {
            throw new \Exception('openssl extension not found');
        }

        if (!extension_loaded('pdo_mysql')) {
            throw new \Exception('pdo_mysql extension not found');
        }

        // silence the error reporting from PDO
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_SILENT);
        $this->pdo = $pdo;

        if (empty($sessionsTableName)) {
            throw new \Exception(sprintf('sessions table name is empty in %s', __METHOD__));
        }
        $this->sessionsTableName = (string)$sessionsTableName;

        if (empty($encryptionKey)) {
            throw new \Exception(sprintf('encryption key is empty in %s', __METHOD__));
        }

        $this->encryptionKey = $encryptionKey;
    }

    /**
     * Workflow: Generate initalisation vector for the current session, encrypt the data using encryption key and
     * generated iv, write the session to database. Default session lifetime (usually defaults to 1440) is taken from
     * php.ini -> session.gc_maxlifetime.
     * @link http://php.net/manual/en/sessionhandlerinterface.write.php
     *
     * @param string $session_id The session id.
     * @param string $session_data
     * The encoded session data. This data is the
     * result of the PHP internally encoding
     * the $_SESSION superglobal to a serialized
     * string and passing it as this parameter.
     * Please note sessions use an alternative serialization method.
     *
     * @return bool The return value (usually TRUE on success, FALSE on failure).
     * @throws \Exception
     * @since 5.4.0
     */
    public function write($session_id, $session_data)
    {
        /**
         * First generate the session initialisation vector (iv) and then
         * use it together with hashed encryption key to encrypt the data, then write the session to the database.
         * @important "iv" must have the same length as the cipher block size (128 bits, aka 16 bytes for AES256).
         * @var string of (psuedo) bytes (in binary form, you need to bin2hex the data if you want hexadecimal
         * representation.
         */
        $iv = openssl_random_pseudo_bytes(self::IV_LENGTH, $strong);

        // should NEVER happen for our cipher mode.
        if (!$strong) {
            throw new \Exception(sprintf('generated iv for the cipher mode "%s" is not strong enough',
                self::CIPHER_MODE));
        }

        $sessionData = base64_encode($this->encrypt($session_data, $iv));
        unset($session_data);

        $sql = $this->pdo->prepare("REPLACE INTO {$this->sessionsTableName} (session_id, modified, session_data, lifetime, iv) 
                                    VALUES (:session_id, NOW(), :session_data, :lifetime, :iv)");

        return $sql->execute([
            'session_id'   => $session_id,
            'session_data' => $sessionData,
            'lifetime'     => ini_get('session.gc_maxlifetime'),
            'iv'           => $iv
        ]);
    }

    /**
     * Encrypts the data with given cipher.
     * Prepends the chekcsum block of hashes.
     *
     * @param $rawPlaintextData
     * @param $iv string binary initialisation vector
     *
     * @return string (raw binary data) format: $encryptedDataHash . $ivHash . $encryptedData
     * @throws \Exception
     */
    protected function encrypt($rawPlaintextData, $iv)
    {
        $integrityHashHmac = hash_hmac(self::HASH_ALGORITHM, $iv . $rawPlaintextData, session_id(), true);
        $hashedEncryptionKey = hash(self::HASH_ALGORITHM, $this->encryptionKey, true);
        $encryptedData = openssl_encrypt($rawPlaintextData, self::CIPHER_MODE, $hashedEncryptionKey, OPENSSL_RAW_DATA,
            $iv);
        unset($rawPlaintextData);

        if (false === $encryptedData) {
            throw new \Exception(sprintf('data encryption failed in %s. error: %s', __METHOD__,
                openssl_error_string()));
        }

        $ivHmac = hash_hmac(self::HASH_ALGORITHM, $iv, session_id(), true);

        return $ivHmac . $encryptedData . $integrityHashHmac;
    }

    /**
     * Read the session, decrypt the data with openssl cipher method, using session IV (initialisation vector)
     * and encryption key and return the decrypted data.
     * @link http://php.net/manual/en/sessionhandlerinterface.read.php
     *
     * @param string $session_id The session id to read data for.
     *
     * @return string
     * Returns an encoded string of the read data.
     * If nothing was read, it must return an empty string.
     * @since 5.4.0
     */
    public function read($session_id)
    {
        $sql = $this->pdo->prepare("SELECT session_data, iv
                                    FROM {$this->sessionsTableName}
                                    WHERE session_id = :session_id 
                                    AND (modified + INTERVAL lifetime SECOND) > NOW()");

        $executed = $sql->execute([
            'session_id' => $session_id,
        ]);

        if ($executed && $sql->rowCount()) {
            $session = $sql->fetchObject();

            return $this->decrypt(base64_decode($session->session_data), $session->iv);
        } else {
            return '';
        }
    }

    /**
     * Decrypts the data, extracts the header checksum,
     * re-calculates every hash and compares with data from checksum,
     * if everything goes well returns decrypted data.
     *
     * @param string $data raw string
     * @param string $iv in binary form
     *
     * @return string decrypted data
     * @throws \Exception
     */
    protected function decrypt($data, $iv)
    {
        // integrity check
        if (strlen($data) < self::IV_LENGTH) {
            throw new \Exception(sprintf('data integrity check failed in %s', strlen($data), self::IV_LENGTH,
                __METHOD__));
        }

        // extract IV hmac from checksum and compare it to the hmac of $iv coming from the database
        $extractedIvHmac = substr($data, 0, self::IV_HMAC_LENGTH);
        $calculatedIvHmac = hash_hmac(self::HASH_ALGORITHM, $iv, session_id(), true);

        if (!hash_equals($extractedIvHmac, $calculatedIvHmac)) {
            throw new \Exception(sprintf('iv hmac check failed in %s', __METHOD__));
        }

        // extract hash hmac from the end of the data
        $extractedHashHmac = substr($data, -self::HMAC_HASH_LENGTH);

        // extract the encrypted data
        $encryptedData = substr($data, self::IV_HMAC_LENGTH, -self::HMAC_HASH_LENGTH);
        unset($data);

        // hash the encryption key before decryption
        $hashedEncryptionKey = hash(self::HASH_ALGORITHM, $this->encryptionKey, true);

        // decrypt the data
        $decryptedData = openssl_decrypt($encryptedData, self::CIPHER_MODE, $hashedEncryptionKey, OPENSSL_RAW_DATA,
            $iv);

        if (false === $decryptedData) {
            throw new \Exception(sprintf('data decryption failed in %s. error: %s', __METHOD__,
                openssl_error_string()));
        }

        $calculatedHashHmac = hash_hmac(self::HASH_ALGORITHM, $iv . $decryptedData, session_id(), true);
        if (!hash_equals($extractedHashHmac, $calculatedHashHmac)) {
            throw new \Exception('data hash hmac mismatch.');
        }

        return $decryptedData;
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
    public function destroy($session_id)
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionsTableName} WHERE session_id = :session_id")->execute([
            'session_id' => $session_id
        ]);
    }

    /**
     * Cleanup old sessions
     * @link http://php.net/manual/en/sessionhandlerinterface.gc.php
     *
     * @param int $maxlifetime
     * Sessions that have not updated for
     * the last maxlifetime seconds will be removed.
     *
     * @return bool
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     */
    public function gc($maxlifetime)
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionsTableName} WHERE (modified + INTERVAL lifetime SECOND) < NOW()")
                         ->execute();
    }

    /**
     * Initialize session
     * @link http://php.net/manual/en/sessionhandlerinterface.open.php
     *
     * @param string $save_path The path where to store/retrieve the session.
     * @param string $session_name The session name.
     *
     * @return bool
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     * @codeCoverageIgnore
     */
    public function open($save_path, $session_name)
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
    public function close()
    {
        return true;
    }

    /**
     * Generate a keyed hash value using the HMAC method
     * @link http://php.net/manual/en/function.hash-hmac.php
     * Key used is session_id.
     *
     * @param string $data Message to be hashed.
     *
     * @return string (binary)
     */
    protected function hmac($data)
    {
        return hash_hmac(self::HASH_ALGORITHM, $data, session_id(), true);
    }
}
