<?php
/*********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                              *
 * Copyright (c) 2017. All rights reserved.                                      *
 *                                                                               *
 * Project Name: Session Save Handler                                            *
 * Repository: https://github.com/drnasin/middleware-collection                  *
 *                                                                               *
 * File: SaveHandler.php                                                         *
 * Last Modified: 13.5.2017 0:44                                                 *
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

namespace App;

/**
 * Custom database session save handler with encrypted session data
 * @package App
 * @author Ante Drnasin
 */
class SessionHandler implements \SessionHandlerInterface
{
    /**
     * Database connection
     * @var \PDO
     */
    protected $dbAdapter;
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
     * @param \PDO $dbAdapter
     * @param      $sessionTable
     */
    public function __construct($dbAdapter, $sessionTableName)
    {
        $this->dbAdapter = $dbAdapter;
        $this->sessionTableName = $sessionTableName;
        register_shutdown_function("session_write_close");
    }

    /**
     * Closes the session. Not needed.
     * @return true
     */
    public function close()
    {
        return true;
    }

    /**
     * Opens the session. Not needed
     *
     * @param string $save_path
     * @param string $session_id
     *
     * @return true
     */
    public function open($save_path, $session_id)
    {
        return true;
    }

    /**
     * Read the session, decrypt the data and return it
     *
     * @param int session id
     *
     * @return string|false
     */
    public function read($id)
    {
        $sql = "SELECT session_data FROM {$this->sessionTableName} WHERE session_id = '{$id}' AND (modified + INTERVAL lifetime SECOND > TIME()) LIMIT 1";
        $result = $this->dbAdapter->query($sql);

        if ($result) {
            if ($result->rowCount()) {
                return base64_decode($result->fetchObject()->session_data);
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Write the session, encrypt the data
     *
     * @param int    $id session id
     * @param string $data session data
     *
     * @return \PDOStatement
     */
    public function write($id, $data)
    {
        // escape the data here. Use your own function
        $data = $this->dbAdapter->escape_string($data);

        $sql = sprintf("SELECT session_id FROM %s WHERE session_id = '%s'", $this->sessionTableName, $id);

        if ($this->dbAdapter->query($sql)->num_rows) {
            $sql = sprintf("UPDATE %s SET modified = '%s',session_data = '%s' WHERE session_id = '%s'",
                $this->sessionTableName, time(), base64_encode($data), $id);

            return $this->dbAdapter->query($sql);
        }

        $sql = sprintf("INSERT INTO %s (session_id, modified, session_data) VALUES('%s', '%s', '%s')",
            $this->sessionTableName, $id, time(), base64_encode($data));

        return $this->dbAdapter->query($sql);
    }

    /**
     * Destoroy the session
     *
     * @param int session id
     *
     * @return bool
     */
    public function destroy($id)
    {
        $sql = sprintf("DELETE FROM %s WHERE 'session_id' = '%s'", $this->sessionTableName,
            $this->dbAdapter->escape_string($id));

        return $this->dbAdapter->query($sql);
    }

    /**
     * Garbage Collector
     *
     * @param int lifetime (sec.)
     *
     * @return bool
     * @see   session.gc_divisor 100
     * @see   session.gc_maxlifetime 1440
     * @see   session.gc_probability 1
     * @usage execution rate 1/100
     * (session.gc_probability/session.gc_divisor)
     */
    public function gc($max)
    {
        $sql = sprintf("DELETE FROM %s WHERE modified < '%s'", $this->sessionTableName, time() - intval($max));

        return $this->dbAdapter->query($sql);
    }
}





