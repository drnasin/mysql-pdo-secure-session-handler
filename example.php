<?php
/*********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                              *
 * Copyright (c) 2017. All rights reserved.                                      *
 *                                                                               *
 * Project Name: Session Save Handler                                            *
 * Repository: https://github.com/drnasin/db-session-save-handler-with-encryption*
 *                                                                               *
 * File: example.php                                                             *
 * Last Modified: 17.5.2017 14:39                                                *
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

include_once './vendor/autoload.php';

$dbSettings = [
    'host'     => '127.0.0.1',
    'port'     => '3306',
    'name'     => 'sessions',
    'username' => 'root',
    'password' => '',
    'charset'  => 'utf8',
];

$sessionTableName = 'sessions';

$dsn = sprintf('mysql:host=%s;dbname=%s;port=%d;charset=%s', $dbSettings['host'], $dbSettings['name'],
    $dbSettings['port'], $dbSettings['charset']);

$pdo = new PDO($dsn, $dbSettings['username'], $dbSettings['password'], [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_OBJ
]);

$handler = new \App\Session\SessionHandler($pdo, $sessionTableName);
session_set_save_handler($handler, true);
session_start();

$_SESSION['test'] = 12;
