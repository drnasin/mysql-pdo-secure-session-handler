<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 21.5.2017 18:44                                                 *
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
     * Database connection
     * @var \PDO
     */
    protected $pdo;
    /**
     * Name of the DB table which handles the sessions
     * @var string
     */
    protected $sessionTableName;
    /**
     * Encryption key (private key).
     * Used in combination with initialisation vector (IV)
     * Value of this secret key can be anything you want as long as you keep it SAFE and PRIVATE!
     * @var string
     */
    protected $secretKey;
    /**
     * Encryption/decryption cipher.
     * Default is 'AES-256-CTR'.
     *
     * @var string
     */
    protected $cipher;

    /**
     * SessionHandler constructor.
     *
     * @param \PDO   $pdo
     * @param string $sessionTableName
     * @param string $secretKey
     * @param string $cipher
     */
    public function __construct(\PDO $pdo, $sessionTableName, $secretKey, $cipher = 'AES-256-CTR')
    {
        $this->pdo = $pdo;
        $this->sessionTableName = $sessionTableName;
        $this->secretKey = $secretKey;
        $this->cipher = $cipher;
    }

    /**
     * Generate initailisation vector, encrypt the data
     * write encrypted session data to DB. Default session lifetime
     * value is taken from
     *
     * session.gc_maxlifetime
     *
     * @param int    $session_id session id
     * @param string $data session data
     *
     * @return bool
     */
    public function write($session_id, $data)
    {
        /**
         * Generate the session initialisation vector (iv) first,
         * which is then used together with $this->secretKey to enrypt/decrypt the session data.
         */
        do {
            $ivSize = 16; // 128 bits
            $iv = openssl_random_pseudo_bytes($ivSize, $strong);
        } while (!$strong);

        $sql = $this->pdo->prepare("REPLACE INTO {$this->sessionTableName} (session_id, modified, session_data, lifetime, init_vector) 
                                    VALUES(:session_id, NOW(), :session_data, :lifetime, :iv)");

        return $sql->execute([
            'session_id'   => $session_id,
            'session_data' => openssl_encrypt($data, $this->cipher, $this->secretKey, 0, $iv),
            'lifetime'     => ini_get('session.gc_maxlifetime'),
            'iv'           => $iv
        ]);
    }

    /**
     * Read the session, decrypt the data using session IV
     * and secretKey (general encryption key) and return it.
     *
     * @param int $session_id session id
     *
     * @return string
     */
    public function read($session_id)
    {
        $sql = $this->pdo->prepare("SELECT session_data, init_vector
                                    FROM {$this->sessionTableName}
                                    WHERE session_id = :session_id 
                                    AND (modified + INTERVAL lifetime SECOND > NOW())");

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
        return $this->pdo->prepare("DELETE FROM {$this->sessionTableName} WHERE session_id = :session_id")->execute([
            'session_id' => $session_id
        ]);
    }

    /**
     * Garbage Collector
     * Lifetime is in the database therefore $lifetime
     * is unused and we can unset it.
     *
     * @param int $lifetime (sec.)
     *
     * @see
     * @return bool
     */
    public function gc($lifetime = 1440)
    {
        unset($lifetime);
        return $this->pdo->prepare("DELETE FROM {$this->sessionTableName} WHERE (modified + INTERVAL lifetime SECOND) < NOW()")
                         ->execute();
    }

    /**
     * Not important for DB handler.
     *
     * @codeCoverageIgnore
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
     * Not important for DB handler.
     *
     * @codeCoverageIgnore
     * @return bool
     */
    public function close()
    {
        return true;
    }
}
