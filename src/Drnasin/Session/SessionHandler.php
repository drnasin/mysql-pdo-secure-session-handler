<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 29.5.2017 21:16                                                 *
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
     * Length (in bytes) of IV
     * @var int
     */
    const IV_LENGTH = 16;
    /**
     * Length of integrity HMAC hash
     * @var int
     */
    const HASH_HMAC_LENGTH = 32;
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
     * 'Encryption key' used for encryption/decryption.
     * Can be from a string (config array for example) or from a file.
     * Just make sure you take care of trimming! (ie. openssl adds EOL at the end of output file)
     * Keep it somewhere SAFE!
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

        // not needed but just in case
        if (self::IV_LENGTH !== openssl_cipher_iv_length(self::CIPHER_MODE)) {
            throw new \Exception(sprintf("IV length for cipher mode %s should be %s. received %s", self::CIPHER_MODE,
                openssl_cipher_iv_length(self::CIPHER_MODE), self::IV_LENGTH));
        }
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
     * @throws \Exception
     * @since 5.4.0
     */
    public function write($session_id, $session_data)
    {
        /**
         * First generate the session initialisation vector (IV) and then
         * use it together with hashed encryption key to encrypt the data, then write the session to the database.
         * @important "IV" must have the same length as the cipher block size (128 bits, aka 16 bytes for AES256).
         * @var string of (psuedo) bytes (in binary form, you need to bin2hex the data if you want hexadecimal
         * representation.
         */
        $iv = openssl_random_pseudo_bytes(self::IV_LENGTH, $strong);

        // should NEVER happen for our cipher mode.
        if (!$strong) {
            throw new \Exception(sprintf('generated IV for the cipher mode "%s" is not strong enough',
                self::CIPHER_MODE));
        }

        // encrypt the data and immediately encode it so we can store it to database
        $encodedEncryptedData = base64_encode($this->encrypt($session_data, $iv));
        unset($session_data); // cleaning

        $sql = $this->pdo->prepare("REPLACE INTO {$this->sessionsTableName} (session_id, modified, session_data, lifetime, iv) 
                                    VALUES (:session_id, NOW(), :session_data, :lifetime, :iv)");

        return $sql->execute([
            'session_id'   => $session_id,
            'session_data' => $encodedEncryptedData,
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
        // calculate the "integrity" hmac
        $integrityHashHmac = hash_hmac(self::HASH_ALGORITHM, $iv . $rawPlaintextData, session_id(), true);

        // hash the encryption key
        $hashedEncryptionKey = hash(self::HASH_ALGORITHM, $this->encryptionKey, true);

        // encrypt the raw data
        $encryptedData = openssl_encrypt($rawPlaintextData, self::CIPHER_MODE, $hashedEncryptionKey, OPENSSL_RAW_DATA,
            $iv);
        unset($rawPlaintextData); // cleaning

        if (false === $encryptedData) {
            throw new \Exception(sprintf('data encryption failed in %s. error: %s', __METHOD__,
                openssl_error_string()));
        }

        // calculate hmac of IV
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
     * @param string $encryptedData raw string
     * @param string $iv in binary form
     *
     * @return string decrypted data
     * @throws \Exception
     */
    protected function decrypt($encryptedData, $iv)
    {
        // integrity check
        if (strlen($encryptedData) < self::IV_LENGTH) {
            throw new \Exception(sprintf('data integrity check failed in %s', __METHOD__));
        }

        // extract IV hmac from checksum block and compare it to the hmac of $iv coming from the database
        $extractedIvHmac = substr($encryptedData, 0, self::HASH_HMAC_LENGTH);
        $calculatedIvHmac = hash_hmac(self::HASH_ALGORITHM, $iv, session_id(), true);
        if (!hash_equals($extractedIvHmac, $calculatedIvHmac)) {
            throw new \Exception(sprintf('IV hmac check failed in %s', __METHOD__));
        }

        // extract integrity hash hmac checksum block from the end of the received data
        $extractedIntegrityHmac = substr($encryptedData, -self::HASH_HMAC_LENGTH);

        // extract the encrypted data
        $extractedEncryptedData = substr($encryptedData, self::HASH_HMAC_LENGTH, -self::HASH_HMAC_LENGTH);
        unset($data); // cleaning

        // hash the encryption key before decryption
        $hashedEncryptionKey = hash(self::HASH_ALGORITHM, $this->encryptionKey, true);

        // decrypt the data
        $decryptedData = openssl_decrypt($extractedEncryptedData, self::CIPHER_MODE, $hashedEncryptionKey,
            OPENSSL_RAW_DATA, $iv);

        if (false === $decryptedData) {
            throw new \Exception(sprintf('data decryption failed in %s. error: %s', __METHOD__,
                openssl_error_string()));
        }

        // calculate integrity hmac and compare with extracted
        $calculatedIntegrityHmac = hash_hmac(self::HASH_ALGORITHM, $iv . $decryptedData, session_id(), true);
        if (!hash_equals($extractedIntegrityHmac, $calculatedIntegrityHmac)) {
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
     * Method used is self::HASH_ALGORITHM
     *
     * @param string $data Message to be hashed.
     *
     * @return string (binary)
     * @see SessionHandler::HASH_ALGORITHM
     */
    protected function hmac($data)
    {
        return hash_hmac(self::HASH_ALGORITHM, $data, session_id(), true);
    }
}
