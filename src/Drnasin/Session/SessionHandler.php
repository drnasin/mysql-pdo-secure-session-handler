<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-session-save-handler          *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 18.5.2017 8:11                                                  *
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
 * Custom database session save handler with encrypted session data using PDO.
 * Lifetime of a session can be "per session" base!
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
     * SessionHandler constructor.
     *
     * @param \PDO   $pdo
     * @param string $sessionTableName
     */
    public function __construct(\PDO $pdo, $sessionTableName)
    {
        $this->pdo = $pdo;
        $this->sessionTableName = $sessionTableName;
    }

    /**
     * Closes the session.
     * Not needed. We are using database so let's
     * use this opportunity to call the garbage collector.
     * @return bool
     */
    public function close()
    {
        return $this->gc();
    }

    /**
     * Garbage Collector.
     * Life time is in the database!
     *
     * @param int $max (sec.)
     *
     * @return bool
     */
    public function gc($max = 0)
    {
        return $this->pdo->prepare('DELETE FROM {$this->sessionTableName} WHERE (modified + INTERVAL lifetime SECOND) < NOW()')
                         ->execute();
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
        return true;
    }

    /**
     * Read the session, decrypt the data and return it.
     *
     * @param int $id session id
     *
     * @return string
     */
    public function read($id)
    {
        $sql = $this->pdo->prepare('SELECT session_data
                                    FROM {$this->sessionTableName}
                                    WHERE session_id = :session_id 
                                    AND (modified + INTERVAL lifetime SECOND > NOW())');

        $result = $sql->execute([
            'session_id' => $id,
        ]);

        if ($result && $sql->rowCount()) {
            return base64_decode($sql->fetchObject()->session_data);
        } else {
            return '';
        }
    }

    /**
     * Write the session, encrypt the data
     *
     * @param int    $id session id
     * @param string $data session data
     *
     * @return bool
     */
    public function write($id, $data)
    {
        $sql = $this->pdo->prepare('REPLACE INTO {$this->sessionTableName} (session_id, modified, session_data, lifetime) 
                                    VALUES(:session_id, NOW(), :session_data, :lifetime)');

        return $sql->execute([
            'session_id'   => $id,
            'session_data' => base64_encode($data),
            'lifetime'     => ini_get('session.gc_maxlifetime')
        ]);
    }

    /**
     * @param string $id
     *
     * @return bool
     */
    public function destroy($id)
    {
        return $this->pdo->prepare('DELETE FROM {$this->sessionTableName} WHERE session_id = :session_id')->execute([
            'session_id' => $id
        ]);
    }
}
