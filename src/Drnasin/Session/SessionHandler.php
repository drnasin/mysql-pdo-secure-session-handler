<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 22.5.2017 16:31                                                 *
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
 * Mysql (PDO) session save handler with session data encryption.
 * This class encrypts the session data using the "encryption key"
 * and initialisation vector (IV) which is generated per session.
 * @package Drnasin\Session
 * @author Ante Drnasin
 */
class SessionHandler implements \SessionHandlerInterface
{
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
     * Value of this key can be anything you want (string, hash or even openssl_random_pseudo_bytes())
     * as long as you keep it SAFE and PRIVATE!
     * @important encryption key is hashed using sha512 before enryption/decryption
     * @var string
     */
    protected $encryptionKey;
    /**
     * Any value from hash_algos() array.
     * Default is sha512
     * @var string
     * @see hash_algos()
     */
    protected $hashAlgo;
    /**
     * Encryption/decryption cipher method.
     * Default is 'AES-256-CTR'.
     * @see openssl_get_cipher_methods()
     * @var string
     */
    protected $cipher;

    /**
     * SessionHandler constructor.
     *
     * @param \PDO   $pdo
     * @param string $sessionsTableName
     * @param string $encryptionKey
     * @param string $hashAlgo
     * @param string $cipher
     *
     * @throws \Exception
     */
    public function __construct(
        \PDO $pdo,
        $sessionsTableName,
        $encryptionKey,
        $hashAlgo = 'sha512',
        $cipher = 'AES-256-CTR'
    ) {
        $this->pdo = $pdo;
        $this->sessionsTableName = $sessionsTableName;

        if (empty($encryptionKey)) {
            throw new \Exception(sprintf('encryption key is empty in %s', __METHOD__));
        }
        $this->encryptionKey = $encryptionKey;

        $hashAlgo = strtolower($hashAlgo);
        if (!in_array($hashAlgo, hash_algos())) {
            throw new \Exception(sprintf("unknown hash algo '%s' received in %s", $hashAlgo, __METHOD__));
        }
        $this->hashAlgo = $hashAlgo;

        if (!in_array($cipher, openssl_get_cipher_methods())) {
            throw new \Exception(sprintf("unknown cipher method '%s' received in %s", $cipher, __METHOD__));
        }
        $this->cipher = $cipher;
    }

    /**
     * Workflow: Generate initalisation vector for the current session, encrypt the data using encryption key and iv,
     * write the session to database. Default session lifetime (usually defaults to 1440) is taken from
     * php.ini -> session.gc_maxlifetime.
     *
     * @param int    $session_id session id
     * @param string $data raw session data
     *
     * @return bool
     */
    public function write($session_id, $data)
    {
        /**
         * First generate the session initialisation vector (iv) and then
         * use it together with encryption key to enrypt/decrypt the session data.
         */
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher));

        $sql = $this->pdo->prepare("REPLACE INTO {$this->sessionsTableName} (session_id, modified, session_data, lifetime, init_vector) 
                                    VALUES (:session_id, NOW(), :session_data, :lifetime, :iv)");

        return $sql->execute([
            'session_id'   => $session_id,
            'session_data' => $this->encrypt($data, $iv),
            'lifetime'     => ini_get('session.gc_maxlifetime'),
            'iv'           => $iv
        ]);
    }

    /**
     * @param $data
     * @param $iv
     *
     * @return string
     * @throws \Exception
     */
    public function encrypt($data, $iv)
    {
        $hashedEncryptionKey = hash($this->hashAlgo, $this->encryptionKey, true);
        $encryptedData = openssl_encrypt($data, $this->cipher, $hashedEncryptionKey, OPENSSL_RAW_DATA, $iv);

        if (false === $encryptedData) {
            throw new \Exception(sprintf('session data encryption failed in %s. encryption error: %s', __METHOD__,
                openssl_error_string()));
        }

        return base64_encode($encryptedData);
    }

    /**
     * Read the session, decrypt the data using session IV (initialisation vector)
     * and secretKey (general encryption key) and return the data.
     *
     * @param int $session_id session id
     *
     * @return string
     */
    public function read($session_id)
    {
        $sql = $this->pdo->prepare("SELECT session_data, init_vector
                                    FROM {$this->sessionsTableName}
                                    WHERE session_id = :session_id 
                                    AND (modified + INTERVAL lifetime SECOND) > NOW()");

        $executed = $sql->execute([
            'session_id' => $session_id,
        ]);

        if ($executed && $sql->rowCount()) {
            $session = $sql->fetchObject();

            return $this->decrypt($session->session_data, $session->init_vector);
        } else {
            return '';
        }
    }

    /**
     * @param $data
     * @param $iv
     *
     * @return string
     * @throws \Exception
     */
    public function decrypt($data, $iv)
    {
        $data = base64_decode($data);
        $hashedEncryptionKey = hash($this->hashAlgo, $this->encryptionKey, true);
        $decryptedData = openssl_decrypt($data, $this->cipher, $hashedEncryptionKey, OPENSSL_RAW_DATA, $iv);

        if (false === $decryptedData) {
            throw new \Exception(sprintf('session data decryption failed in %s. decryption error: %s', __METHOD__,
                openssl_error_string()));
        }

        return $decryptedData;
    }

    /**
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
     * Lifetime of a session is stored in the database,
     * therefore $lifetime is not used.
     *
     * @param int $lifetime (sec.)
     *
     * @return bool
     * @see \SessionHandlerInterface::gc()
     */
    public function gc($lifetime = null)
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
