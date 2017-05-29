<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionsTest.php                                                         *
 * Last Modified: 27.5.2017 22:45                                                 *
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

use PHPUnit\Framework\TestCase;

class SessionsTest extends TestCase
{
    /**
     * @var \PDO
     */
    protected $pdo;
    /**
     * @var SessionHandler
     */
    protected $handler;
    /**
     * This is our 'general encryption key'
     * @var string
     */
    protected $encryptionKey;

    protected $sessionId;

    /**
     * Hate using globals but this is a phpunit mechanism of exposing
     * php variables from phpunit.xml so it is what it is.
     * Function is called before running any tests.
     */
    public function setUp()
    {
        $dsn = sprintf($GLOBALS['DB_DSN'], $GLOBALS['DB_HOST'], $GLOBALS['DB_NAME'], $GLOBALS['DB_PORT'], $GLOBALS['DB_CHARSET']);
        $this->pdo = new \PDO($dsn, $GLOBALS['DB_USER'], $GLOBALS['DB_PASS']);
        $this->encryptionKey = trim(file_get_contents($GLOBALS['TEST_ENCRYPTION_KEY_FILE']));
        $this->handler = new SessionHandler($this->pdo, $GLOBALS['DB_TABLENAME'], $this->encryptionKey);

        if(!session_set_save_handler($this->handler, true)) {
            throw new \Exception('session handler for testing not set!');
        }

        $this->sessionId = md5('test');
        session_id($this->sessionId);
        $this->assertTrue(session_start());

        $_SESSION['testSession'] = 'testData';

        $obj = new \stdClass();
        $obj->hash = md5(__NAMESPACE__);

        $_SESSION['testSessionObject'] = $obj;
        session_write_close();
    }

    /**
     * @runInSeparateProcess
     */
    public function testSessionExists() {
        $this->assertEquals($this->sessionId, session_id());
        $this->assertTrue(isset($_SESSION['testSession']));
        $this->assertEquals('testData', $_SESSION['testSession']);
    }

    /**
     * @runInSeparateProcess
     */
    public function testSessionChangeValue() {
        $this->assertTrue(isset($_SESSION['testSession']));
        $this->assertEquals('testData', $_SESSION['testSession']);

        $_SESSION['testSession'] = 'new data';

        $this->assertEquals('new data', $_SESSION['testSession']);
    }

    /**
     * @runInSeparateProcess
     */
    public function testSessionValUnset() {
        $this->assertEquals($this->sessionId, session_id());
        $this->assertTrue(isset($_SESSION['testSession']));
        $sessionData = $this->handler->read($this->sessionId);
        $this->assertNotEmpty($sessionData);
        unset($_SESSION['testSession']);
        $this->assertFalse(isset($_SESSION['testSession']));
    }

    /**
     * @runInSeparateProcess
     */
    public function testSessionEncode() {
        $this->assertEquals(session_encode(), $this->handler->read($this->sessionId));
    }

    /**
     * @runInSeparateProcess
     */
    public function testObjectInSession() {
        $this->assertTrue(is_object($_SESSION['testSessionObject']));
        $this->assertEquals($_SESSION['testSessionObject']->hash,  md5(__NAMESPACE__));
    }

    /**
     * @runInSeparateProcess
     */
    public function testDestroySession() {
        session_start();
        $this->assertTrue(isset($_SESSION['testSession']));
        $this->assertTrue(isset($_SESSION['testSessionObject']));
        $this->assertNotEmpty($this->handler->read($this->sessionId));
        $_SESSION = [];
        session_write_close();
        $this->assertEmpty($this->handler->read($this->sessionId));
        $this->assertFalse(isset($_SESSION['testSession']));
        $this->assertFalse(isset($_SESSION['testSessionObject']));
    }

}
