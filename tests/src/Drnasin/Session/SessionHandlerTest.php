<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-session-save-handler          *
 *                                                                                *
 * File: SessionHandlerTest.php                                                   *
 * Last Modified: 19.5.2017 19:51                                                 *
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

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

/**
 * Class SessionHandlerTest
 * @package Drnasin\Session
 * @author  Ante Drnasin
 * @link    https://www.drnasin.com
 */
class SessionHandlerTest extends TestCase
{
    protected $pdo;

    public function setUp()
    {
        $dsn = sprintf($GLOBALS['DB_DSN'], $GLOBALS['DB_HOST'], $GLOBALS['DB_NAME'], $GLOBALS['DB_PORT'],
            $GLOBALS['DB_CHARSET']);
        $this->pdo = new \PDO($dsn, $GLOBALS['DB_USER'], $GLOBALS['DB_PASS']);
    }

    public function testConstructor()
    {
        $handler = new SessionHandler($this->pdo, "sessions", hash('sha512', 'tests'));
        Assert::assertAttributeEquals($this->pdo, 'pdo', $handler);
        Assert::assertAttributeEquals('sessions', 'sessionTableName', $handler);
        Assert::assertAttributeEquals(hash('sha512', 'tests'), 'secretKey', $handler);
    }
}
