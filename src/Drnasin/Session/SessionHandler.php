<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 22.5.2017 9:29                                                  *
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
 * This class encrypts the session data using secretKey ("encryption key")
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
     * 'Encryption key' (or 'Secret key').
     * Used in combination with session's initialisation vector (IV) to encrypt/decrypt the session data.
     * Value of this key can be anything you want (string, hash or even openssl_random_pseudo_bytes())
     * as long as you keep it SAFE and PRIVATE! If you lose it you are screwed. That's why you have options
     * regarding "complexity" (you can't really "remember" value from openssl_random_pseudo_bytes() now can you? :) )
     * I suggest using sha512 hash of a secret word as a secretKey. Should be more than enough for majority of people
     * in dev/land. Reminder: hash('sha512', '<secret-word>');
     * @var string
     */
    protected $secretKey;
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
     * @param string $secretKey
     * @param string $cipher
     *
     * @throws \Exception
     */
    public function __construct(\PDO $pdo, $sessionsTableName, $secretKey, $cipher = 'AES-256-CTR')
    {
        $this->pdo = $pdo;
        $this->sessionsTableName = $sessionsTableName;

        if (empty($secretKey)) {
            throw new \Exception(sprintf('secret key is empty in %s', __METHOD__));
        }
        $this->secretKey = $secretKey;

        if (!in_array($cipher, openssl_get_cipher_methods())) {
            throw new \Exception(sprintf("unkown cipher method '%s' received in %s", $cipher, __METHOD__));
        }
        $this->cipher = $cipher;
    }

    /**
     * Workflow: Generate initalisation vector for the current session, encrypt the data using IV and $this->secretkey,
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
         * use it together with $this->secretKey to enrypt/decrypt the session data.
         */
        do {
            $ivSize = 16; // 128 bits
            $iv = openssl_random_pseudo_bytes($ivSize, $strong);
        } while (!$strong);

        $sql = $this->pdo->prepare("REPLACE INTO {$this->sessionsTableName} (session_id, modified, session_data, lifetime, init_vector) 
                                    VALUES (:session_id, NOW(), :session_data, :lifetime, :iv)");

        return $sql->execute([
            'session_id'   => $session_id,
            'session_data' => openssl_encrypt($data, $this->cipher, $this->secretKey, 0, $iv),
            'lifetime'     => ini_get('session.gc_maxlifetime'),
            'iv'           => $iv
        ]);
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

        $result = $sql->execute([
            'session_id' => $session_id,
        ]);

        if ($result && $sql->rowCount()) {
            $session = $sql->fetchObject();

            return openssl_decrypt($session->session_data, $this->cipher, $this->secretKey, 0, $session->init_vector);
        } else {
            return '';
        }
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
     * Lifetime of session is stored is in the database therefore $lifetime
     * is not used.
     *
     * @param int $lifetime (sec.)
     *
     * @return bool
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
