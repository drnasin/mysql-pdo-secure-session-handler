<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 27.5.2017 17:07                                                 *
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
    const CHECKUM_BLOCK_LENGTH = 32;
    /**
     * checksum header prepended to data.
     * header consists of hash(encryptedData)+hash(authString)+hash(iv)
     * @var int
     */
    const CHECKSUM_HEADER_LENTGH = 96; //32*3
    /**
     * Database connection.
     * @var \PDO
     */
    protected $pdo;
    /**
     * Name of the DB table which handles the sessions.
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
     * Encryption key, hashed using:
     * hash($hashAlgorithm, $encryptionKey);
     * @var string
     */
    protected $hashedEncryptionKey;
    /**
     * Used in enc/dec process
     * @var string
     */
    private $authString = 'Drnasin|SessionHandler|1.5.0';

    /**
     * SessionHandler constructor.
     *
     * @param \PDO $pdo
     * @param      $sessionsTableName
     * @param      $encryptionKey
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

        $this->pdo = $pdo;

        if (empty($sessionsTableName)) {
            throw new \Exception(sprintf('sessions table name is empty in %s', __METHOD__));
        }
        $this->sessionsTableName = (string)$sessionsTableName;

        if (empty($encryptionKey)) {
            throw new \Exception(sprintf('encryption key is empty in %s', __METHOD__));
        }

        $this->encryptionKey = $encryptionKey;

        /**
         * Hash the encryption key using sha256.
         * openssl_digest() does the same as hash() function.
         * Last parameter, if set to true, will return BINARY data,otherwise hex.
         */
        $this->hashedEncryptionKey = openssl_digest($encryptionKey, self::HASH_ALGORITHM, true);
    }

    /**
     * Workflow: Generate initalisation vector for the current session, encrypt the data using encryption key and
     * generated iv, write the session to database. Default session lifetime (usually defaults to 1440) is taken from
     * php.ini -> session.gc_maxlifetime.
     *
     * @param int    $session_id session id
     * @param string $data raw session data
     *
     * @return bool
     * @throws \Exception
     */
    public function write($session_id, $data)
    {
        /**
         * First generate the session initialisation vector (iv) and then
         * use it together with hashed encryption key to encrypt the data, then write the session to the database.
         * @important "iv" must have the same length as the cipher block size (128 bits, aka 16 bytes for AES256).
         * @var string of (psuedo) bytes (in binary form, you need to bin2hex the data if you want hexadecimal
         *      representation.
         */
        $iv = openssl_random_pseudo_bytes(self::IV_LENGTH, $strong);

        // should NEVER happen for our cipher mode.
        if (!$strong) {
            throw new \Exception(sprintf('generated iv for the cipher mode "%s" is not strong enough',
                self::CIPHER_MODE));
        }

        $encryptedData = $this->encrypt($data, $iv);

        $sql = $this->pdo->prepare("REPLACE INTO {$this->sessionsTableName} (session_id, modified, session_data, lifetime, iv) 
                                    VALUES (:session_id, NOW(), :session_data, :lifetime, :iv)");

        return $sql->execute([
            'session_id'   => $session_id,
            'session_data' => base64_encode($encryptedData),
            'lifetime'     => ini_get('session.gc_maxlifetime'),
            'iv'           => $iv
        ]);
    }

    /**
     * Encrypts the data with given cipher.
     * Prepends the chekcsum block of hashes.
     *
     * @param $data
     * @param $iv string binary initialisation vector
     *
     * @return string (raw binary data)
     *          $encryptedDataHash . $authStringhash . $ivHash . $encryptedData
     * @throws \Exception
     */
    protected function encrypt($data, $iv)
    {
        /**
         * Because of OPENSSL_RAW_DATA - data needs to be raw (not encoded).
         */
        $encryptedData = openssl_encrypt($data, self::CIPHER_MODE, $this->hashedEncryptionKey, OPENSSL_RAW_DATA, $iv);

        if (false === $encryptedData) {
            throw new \Exception(sprintf('data encryption failed in %s. error: %s', __METHOD__,
                openssl_error_string()));
        }

        $encryptedDataHash = openssl_digest($encryptedData, self::HASH_ALGORITHM, true);
        $ivHash = openssl_digest($iv, self::HASH_ALGORITHM, true);
        $authStringhash = openssl_digest($this->authString, self::HASH_ALGORITHM, true);

        return $encryptedDataHash . $authStringhash . $ivHash . $encryptedData;
    }

    /**
     * Read the session, decrypt the data with openssl cipher method, using session IV (initialisation vector)
     * and encryption key and return the decrypted data.
     *
     * @param int $session_id session id
     *
     * @return string
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
     * Decrypts the datam extracts the header checksum,
     * re-calculate every hash and compare with checksum
     *
     * @param string $data raw string
     * @param string $iv
     *
     * @return string
     * @throws \Exception
     */
    protected function decrypt($data, $iv)
    {
        // integrity check
        if (strlen($data) < self::IV_LENGTH) {
            throw new \Exception(sprintf('data integrity check failed in %s', strlen($data), self::IV_LENGTH,
                __METHOD__));
        }

        // extract check header
        $checksum = substr($data, 0, self::CHECKSUM_HEADER_LENTGH);

        // extract Data hash
        $extractedDataHash = substr($checksum, 0, self::CHECKUM_BLOCK_LENGTH);

        // extract Auth string hash
        $extractedAuthStringHash = substr($checksum, self::CHECKUM_BLOCK_LENGTH, self::CHECKUM_BLOCK_LENGTH);

        // extract IV hash
        $extractedIvHash = substr($checksum, self::CHECKUM_BLOCK_LENGTH * 2, self::CHECKUM_BLOCK_LENGTH);

        // rest is encrypted data
        $encryptedData = substr($data, self::CHECKSUM_HEADER_LENTGH);

        // re-calculate data hash
        $calculatedDataHash = openssl_digest($encryptedData, self::HASH_ALGORITHM, true);

        // re-calculate IV hash
        $calculatedIvHash = openssl_digest($iv, self::HASH_ALGORITHM, true);

        // re-calculate Auth String hash
        $calculatedAuthStringHash = openssl_digest($this->authString, self::HASH_ALGORITHM, true);

        // compare everything
        if (!hash_equals($extractedDataHash, $calculatedDataHash)) {
            throw new \Exception(sprintf('data hash check failed in %s', __METHOD__));
        }

        if (!hash_equals($extractedAuthStringHash, $calculatedAuthStringHash)) {
            throw new \Exception(sprintf('auth hash check failed in %s', __METHOD__));
        }

        if (!hash_equals($extractedIvHash, $calculatedIvHash)) {
            throw new \Exception(sprintf('IV hash check failed in %s', __METHOD__));
        }

        $decryptedData = openssl_decrypt($encryptedData, self::CIPHER_MODE, $this->hashedEncryptionKey,
            OPENSSL_RAW_DATA, $iv);

        if (false === $decryptedData) {
            throw new \Exception(sprintf('data decryption failed in %s. error: %s', __METHOD__,
                openssl_error_string()));
        }

        return $decryptedData;
    }

    /**
     * Deletes the session from the database.
     *
     * @param string $session_id
     *
     * @return bool
     */
    public function destroy($session_id)
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionsTableName} WHERE session_id = :session_id")->execute([
            'session_id' => $session_id
        ]);
    }

    /**
     * Garbage Collector.
     * Lifetime of a session is stored in the database, therefor $lifetime is not used.
     *
     * @param int $lifetime (sec.)
     *
     * @return bool
     * @see \SessionHandlerInterface::gc()
     */
    public function gc($lifetime = 1440)
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionsTableName} WHERE (modified + INTERVAL lifetime SECOND) < NOW()")
                         ->execute();
    }

    /**
     * Not important for database save handler.
     * @codeCoverageIgnore
     *
     * @param string $save_path
     * @param string $session_id
     *
     * @return bool
     */
    public function open($save_path, $session_id)
    {
        return true;
    }

    /**
     * Not important for database save handler.
     * @codeCoverageIgnore
     * @return bool
     */
    public function close()
    {
        return true;
    }
}
