<?php
/*********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                              *
 * Copyright (c) 2017. All rights reserved.                                      *
 *                                                                               *
 * Project Name: Session Save Handler                                            *
 * Repository: https://github.com/drnasin/db-session-save-handler-with-encryption*
 *                                                                               *
 * File: SaveHandler.php                                                         *
 * Last Modified: 15.5.2017 13:19                                                *
 *                                                                               *
 * The MIT License                                                               *
 *                                                                               *
 * Permission is hereby granted, free of charge, to any person obtaining a copy  *
 * of this software and associated documentation files (the "Software"), to deal *
 * in the Software without restriction, including without limitation the rights  *
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell     *
 * copies of the Software, and to permit persons to whom the Software is         *
 * furnished to do so, subject to the following conditions:                      *
 *                                                                               *
 * The above copyright notice and this permission notice shall be included in    *
 * all copies or substantial portions of the Software.                           *
 *                                                                               *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    *
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      *
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   *
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        *
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, *
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN     *
 * THE SOFTWARE.                                                                 *
 *********************************************************************************/

namespace App\Session;

/**
 * Class Session Save Handler.
 * Custom database session save handler with encrypted session data using PDO.
 * @package App\Session
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
     * Session lifetime (for gc) in seconds
     * @var int
     */
    protected $lifetime;

    /**
     * SessionHandler constructor.
     *
     * @param \PDO   $pdo
     * @param string $sessionTableName
     */
    public function __construct(\PDO $pdo, string $sessionTableName)
    {
        $this->pdo = $pdo;
        $this->sessionTableName = $sessionTableName;
        register_shutdown_function('session_write_close');
    }

    /**
     * Closes the session.
     * Not needed. We are using database.
     * @return bool
     */
    public function close() : bool
    {
        return true;
    }

    /**
     * Opens the session.
     * Not needed. We are using database.
     *
     * @param string $save_path
     * @param string $session_id
     *
     * @return bool
     */
    public function open($save_path, $session_id) : bool
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
    public function read($id) : string
    {
        $sql = $this->pdo->prepare("SELECT session_data
                                    FROM {$this->sessionTableName}
                                    WHERE session_id = :session_id 
                                    AND (modified + INTERVAL lifetime SECOND > TIME())
                                    LIMIT 1");
        $result = $sql->execute([
            'session_id' => $id
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
    public function write($id, $data) : bool
    {
        $sql = $this->pdo->prepare("SELECT 
                                      EXISTS(SELECT 1 FROM {$this->sessionTableName} WHERE session_id = :session_id)
                                    AS session_exists");
        $sql->execute([
            'session_id' => $id
        ]);

        if (boolval($sql->fetchObject()->session_exists)) {
            return $this->pdo->prepare("UPDATE {$this->sessionTableName} 
                                        SET modified = CURRENT_TIMESTAMP,
                                            session_data = :session_data
                                      WHERE session_id = :session_id")->execute([
                'session_data' => base64_encode($data),
                'session_id'   => $id
            ]);
        }
    }

    /**
     * @param string $id
     *
     * @return bool
     */
    public function destroy($id) : bool
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionTableName} WHERE 'session_id' = :session_id")->execute([
            'session_id' => $id
        ]);
    }

    /**
     * Garbage Collector
     *
     * @param int $max (sec.)
     *
     * @return bool
     * @see   session.gc_divisor 100
     * @see   session.gc_maxlifetime 1440
     * @see   session.gc_probability 1
     * @usage execution rate 1/100
     * (session.gc_probability/session.gc_divisor)
     */
    public function gc($max) : bool
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionTableName} WHERE modified < :modified")
                         ->execute([
                'modified' => time() - intval($max)
            ]);
    }
}





