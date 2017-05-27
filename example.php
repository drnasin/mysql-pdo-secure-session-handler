<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: example.php                                                              *
 * Last Modified: 27.5.2017 15:34                                                 *
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

/**
 * Encryption key.
 * make sure you keep it SAFE otherwise no sessions can be decrypted!
 */
$encryptionKey = file_get_contents(__DIR__ . '/storage/enc.key');

$dsn = sprintf('mysql:host=%s;dbname=%s;port=%d;charset=%s', $dbSettings['host'], $dbSettings['name'],
    $dbSettings['port'], $dbSettings['charset']);

$handler = new \Drnasin\Session\SessionHandler(
    new PDO($dsn, $dbSettings['username'], $dbSettings['password']),
    $sessionTableName,
    $encryptionKey
);
session_set_save_handler($handler, true);
session_start();

$id = bin2hex(openssl_random_pseudo_bytes(32));
//generate 50 random sessions
for($i = 1; $i <= 50; $i++) {
    $_SESSION["session_{$i}"]['test'] = bin2hex(openssl_random_pseudo_bytes(32));
}
$_SESSION["session_5"]['test'] = 'test';
//should print 50
echo count($_SESSION), PHP_EOL;

//should print 'test'
echo $_SESSION['session_5']['test'], PHP_EOL;

$_SESSION['testSession'] = hash('sha256', $_SESSION["session_5"]['test']);

if($_SESSION['testSession'] === hash('sha256', 'test')) {
    print("working!");
}

