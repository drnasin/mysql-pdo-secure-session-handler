<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: example.php                                                              *
 * Last Modified: 30.5.2017 0:15                                                  *
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

include_once __DIR__ . '/vendor/autoload.php';

$dbSettings = [
    'host'     => '127.0.0.1',
    'port'     => '3306',
    'name'     => 'sessions',
    'table'    => 'sessions_test',
    'username' => 'root',
    'password' => '',
    'charset'  => 'utf8',
];
// set up PDO
$dsn = sprintf('mysql:host=%s;dbname=%s;port=%d;charset=%s', $dbSettings['host'], $dbSettings['name'],
    $dbSettings['port'], $dbSettings['charset']);

$pdo = new PDO($dsn, $dbSettings['username'], $dbSettings['password']);

/**
 * Encryption key.
 * make sure you keep it SAFE otherwise no sessions can be decrypted!
 */
$encryptionKey = trim(file_get_contents(__DIR__ . '/tests/encryption.key'));

try {
    $handler = new \Drnasin\Session\SessionHandler($pdo, $dbSettings['table'], $encryptionKey);
} catch (Exception $e) {
    error_log($e->getMessage());
    die();
}

session_set_save_handler($handler, true);

// we need output buffering because we will use session_start() many time
ob_start();
$createdSessionIds = [];

//open 10 sessions and assign values to the SAME variable in every session
for ($i = 1; $i <= 10; $i++) {
    // generate session id
    $sessionId = session_create_id();
    // set our created session id as session id of next created session
    session_id($sessionId);
    //now start/create the session withour id
    session_start();
    //access the session via superglobal and set value of key 'someKey'
    $_SESSION['someKey'] = sprintf("Setting initial value of var '%s' in session %s", 'someKey', $sessionId);
    // explicitly call session_write_close() (not destroy!) because in the next iteration we are again opening a new session
    session_write_close();

    //store opened sessionId and move on
    $createdSessionIds[] = $sessionId;
}

// walk through all opened sessions
foreach ($createdSessionIds as $createdSessionId) {
    // and re-open each
    session_id($createdSessionId);
    session_start();
    //print value of someKey in that session
    echo $_SESSION["someKey"], PHP_EOL;
    // change the value
    $_SESSION["someKey"] = sprintf("Updated value of var '%s' in session %s", 'someKey', $createdSessionId);
    echo $_SESSION["someKey"], PHP_EOL;
    // again, explicit call becaue of the next iteration.
    session_write_close();
}

//destroy all created sessions
foreach ($createdSessionIds as $createdSessionId) {
    // set session id
    session_id($createdSessionId);
    // re-open the session
    session_start();
    //destroy it (delete)
    if (session_destroy()) {
        echo "Session ", $createdSessionId, " destroyed.", PHP_EOL;
    }
}

// flush the buffer
ob_end_flush();
