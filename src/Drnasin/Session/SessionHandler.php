<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-session-save-handler          *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 19.5.2017 19:32                                                 *
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
 * This class encrypts the session data using secretKey (encrption key)
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
     * Used in combination with initialisation vector (IV) which is generated for every session.
     * Value of this secret key can be anything you want as long as you keep it SAFE and PRIVATE!
     * @var string
     */
    protected $secretKey;

    /**
     * SessionHandler constructor.
     *
     * @param \PDO   $pdo
     * @param string $sessionTableName
     * @param string $secretKey
     */
    public function __construct(\PDO $pdo, $sessionTableName, $secretKey)
    {
        $this->pdo = $pdo;
        $this->sessionTableName = $sessionTableName;
        $this->secretKey = $secretKey;
    }

    /**
     * Opens the session.
     *
     * @param string $save_path
     * @param string $session_id
     *
     * @return bool
     */
    public function open($save_path, $session_id)
    {
        return $this->gc();
    }

    /**
     * Garbage Collector.
     * Life time is in the database!
     *
     * @param int $max (sec.) UNUSED
     *
     * @return bool
     */
    public function gc($max = 0)
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionTableName} WHERE (modified + INTERVAL lifetime SECOND) < NOW()")
                         ->execute();
    }

    /**
     * Closes the session.
     * @return bool
     */
    public function close()
    {
        return true;
    }

    /**
     * Write the session, encode the data
     *
     * @param int    $session_id session id
     * @param string $data session data
     *
     * @return bool
     */
    public function write($session_id, $data)
    {
        do {
            $ivSize = 16; // 128 bits
            $iv = openssl_random_pseudo_bytes($ivSize, $strong);
        } while (!$strong);

        $sql = $this->pdo->prepare("REPLACE INTO {$this->sessionTableName} (session_id, modified, session_data, lifetime, init_vector) 
                                    VALUES(:session_id, NOW(), :session_data, :lifetime, :iv)");

        return $sql->execute([
            'session_id'   => $session_id,
            'session_data' => $this->encrypt($data, $iv),
            'lifetime'     => ini_get('session.gc_maxlifetime'),
            'iv'           => $iv
        ]);
    }

    /**
     * @param string $data
     * @param string $iv
     *
     * @return string
     */
    protected function encrypt($data, $iv)
    {
        return openssl_encrypt($data, 'AES-256-CTR', $this->secretKey, 0, $iv);
    }

    /**
     * Read the session, decrypt the data and return it.
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
            return $this->decrypt($sql->fetchObject()->session_data, $sql->fetchObject()->init_vector);
        } else {
            return '';
        }
    }

    /**
     * @param $data
     * @param $iv
     *
     * @return bool|string
     */
    protected function decrypt($data, $iv)
    {
        return openssl_decrypt($data, 'AES-256-CTR', $this->secretKey, 0, $iv);
    }

    /**
     * @param string $id
     *
     * @return bool
     */
    public function destroy($id)
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionTableName} WHERE session_id = :session_id")->execute([
            'session_id' => $id
        ]);
    }
}
