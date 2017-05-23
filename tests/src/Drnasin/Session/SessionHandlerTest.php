<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionHandlerTest.php                                                   *
 * Last Modified: 23.5.2017 14:15                                                 *
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

/**
 * Class SessionHandlerTest
 * @package Drnasin\Session
 * @author  Ante Drnasin
 */
class SessionHandlerTest extends TestCase
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

    /**
     * Hate using globals but this is a phpunit mechanism of exposing
     * php variables from phpunit.xml so it is what it is.
     * Function is called before running any tests.
     */
    public function setUp()
    {
        $dsn = sprintf($GLOBALS['DB_DSN'], $GLOBALS['DB_HOST'], $GLOBALS['DB_NAME'], $GLOBALS['DB_PORT'], $GLOBALS['DB_CHARSET']);
        $this->pdo = new \PDO($dsn, $GLOBALS['DB_USER'], $GLOBALS['DB_PASS']);
        $this->encryptionKey = hash('sha256', 'some-secret-key');
        $this->handler = new SessionHandler($this->pdo, $GLOBALS['DB_TABLENAME'], $this->encryptionKey);
    }

    /**
     * Constructor test.
     */
    public function testConstructor()
    {
        $this->assertAttributeEquals($this->pdo, 'pdo', $this->handler);
        $this->assertAttributeEquals($GLOBALS['DB_TABLENAME'], 'sessionsTableName', $this->handler);
        $this->assertAttributeEquals($this->encryptionKey, 'encryptionKey', $this->handler);
    }

    /**
     * @group negative-tests
     * @expectedException \Exception
     */
    public function testConstructorUsingUnknownHashAlgo()
    {
        (new SessionHandler($this->pdo, $GLOBALS['DB_TABLENAME'], $this->encryptionKey, 'NonExistingHashAlgo'));
    }

    /**
     * @group negative-tests
     * @expectedException \Exception
     */
    public function testConstructorUsingUnknownCipherMethod()
    {
        (new SessionHandler($this->pdo, $GLOBALS['DB_TABLENAME'], $this->encryptionKey, 'sha256', 'NonExistingCipher'));
    }

    /**
     * @param string $sessionId
     * @param string $sessionData
     *
     * @group negative-tests
     * @dataProvider sessionProvider
     */
    public function testUnknownTableName($sessionId, $sessionData)
    {
        $handler = new SessionHandler($this->pdo, 'NonExistingTable', $this->encryptionKey);
        $this->assertFalse($handler->write($sessionId, $sessionData));
    }

    /**
     * @group negative-tests
     * @expectedException \Exception
     */
    public function testConstructorUsingEmptyEncryptionKey()
    {
        (new SessionHandler($this->pdo, $GLOBALS['DB_TABLENAME'], ''));
    }

    /**
     * @param string $sessionId
     * @param string $sessionData
     *
     * @dataProvider sessionProvider
     */
    public function testSessionWrite($sessionId, $sessionData)
    {
        $this->assertTrue($this->handler->write($sessionId, $sessionData));
    }

    /**
     * @param string $sessionId
     * @param string $sessionData
     *
     * @depends      testSessionWrite
     * @dataProvider sessionProvider
     */
    public function testSessionRead($sessionId, $sessionData)
    {
        $this->assertEquals($sessionData, $this->handler->read($sessionId));
    }

    /**
     * @param string $sessionId
     *
     * @depends      testSessionRead
     * @dataProvider sessionProvider
     */
    public function testSessionDestroy($sessionId)
    {
        $this->assertTrue($this->handler->destroy($sessionId));
    }

    /**
     * Test garbage collecting.
     */
    public function testSessionGarbageCollector()
    {
        $this->assertTrue($this->handler->gc());
    }

    /**
     * @group negative-tests
     */
    public function testNonExistingSessionId()
    {
        $nonExistingSessionId = bin2hex(openssl_random_pseudo_bytes(16));
        $this->assertEmpty($this->handler->read($nonExistingSessionId));
    }

    /**
     * Data provider function
     * @return array
     */
    public function sessionProvider()
    {
        $sessionId = md5(__NAMESPACE__);
        $sessionData = 'Lorem ipsum dolor sit amet';

        return [
            [$sessionId, $sessionData]
        ];
    }
}
