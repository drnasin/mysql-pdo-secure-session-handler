<?php
/**********************************************************************************
 * Created by Ante Drnasin - http://www.drnasin.com                               *
 * Copyright (c) 2017. All rights reserved.                                       *
 *                                                                                *
 * Project Name: Session Save Handler                                             *
 * Repository: https://github.com/drnasin/mysql-pdo-secure-session-handler        *
 *                                                                                *
 * File: SessionHandler.php                                                       *
 * Last Modified: 30.5.2017 19:59                                                 *
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
 * Mysql (PDO) session save handler with openssl session data encryption.
 * This class encrypts the session data using the "encryption key"
 * and initialisation vector (IV) which is generated per session.
 * @package Drnasin\Session
 * @author Ante Drnasin
 * @link https://github.com/drnasin/mysql-pdo-secure-session-handler
 */
class SessionHandler implements \SessionHandlerInterface
{
    /**
     * Hash algorithm used
     * @var string
     */
    const HASH_ALGORITHM = 'SHA256';
    /**
     * Cipher mode used for encryption/decryption
     * @var string
     */
    const CIPHER_MODE = 'AES-256-CBC';
    /**
     * Length (in bytes) of IV
     * @var int
     */
    const IV_LENGTH = 16;
    /**
     * Length of integrity HMAC hash
     * @var int
     */
    const HASH_HMAC_LENGTH = 32;
    /**
     *
     */
    const AUTH_STRING = 'Drnasin-Secure-Session-Handler';
    /**
     * Database connection.
     * @var \PDO
     */
    protected $pdo;
    /**
     * Name of the DB table which holds the sessions.
     * @var string
     */
    protected $sessionsTableName;
    /**
     * 'Encryption key' used for encryption/decryption.
     * Can be from a string (config array for example) or from a file.
     * Just make sure you take care of trimming! (ie. openssl adds EOL at the end of output file)
     * Keep it somewhere SAFE!
     * @var string
     */
    protected $encryptionKey;
    /**
     * @var string
     */
    protected $hashedEncryptionKey;
    /**
     * @var string
     */
    protected $authenticationKey;

    /**
     * SessionHandler constructor.
     * Make sure $encryptionKey is trimmed!
     *
     * @param \PDO   $pdo
     * @param string $sessionsTableName
     * @param string $encryptionKey
     *
     * @throws \Exception
     */
    public function __construct(\PDO $pdo, $sessionsTableName, $encryptionKey)
    {
        if (!extension_loaded('openssl')) {
            throw new \Exception('openssl extension not found');
        }

        if (!extension_loaded('pdo_mysql')) {
            throw new \Exception('pdo_mysql extension not found');
        }

        // silence the error reporting from PDO
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_SILENT);
        $this->pdo = $pdo;

        if (empty($sessionsTableName)) {
            throw new \Exception(sprintf('sessions table name is empty in %s', __METHOD__));
        }
        $this->sessionsTableName = (string)$sessionsTableName;

        if (empty($encryptionKey)) {
            throw new \Exception(sprintf('encryption key is empty in %s', __METHOD__));
        }

        $this->encryptionKey = $encryptionKey;
        // needed for encryption/decryption of plaintext data
        $this->hashedEncryptionKey = hash(self::HASH_ALGORITHM, $encryptionKey, true);

        // calculate authentication key
        $salt = hash(self::HASH_ALGORITHM, session_id() . self::AUTH_STRING, true);
        $this->authenticationKey = $this->hash_hkdf(self::HASH_ALGORITHM, $encryptionKey, 32, self::AUTH_STRING, $salt);

        // not needed but just in case
        if (self::IV_LENGTH !== openssl_cipher_iv_length(self::CIPHER_MODE)) {
            throw new \Exception(sprintf("IV length for cipher mode %s should be %s. received %s", self::CIPHER_MODE,
                openssl_cipher_iv_length(self::CIPHER_MODE), self::IV_LENGTH));
        }
    }

    /**
     * hash_hkdf()
     * An RFC5869-compliant HMAC Key Derivation Function implementation.
     * @author  https://github.com/narfbg/hash_hkdf_compat
     * @link    https://secure.php.net/hash_hkdf
     * @link    https://tools.ietf.org/rfc/rfc5869.txt
     *
     * @param    string $algo Hashing algorithm
     * @param    string $ikm Input keying material
     * @param    int    $length Desired output length
     * @param    string $info Context/application-specific info
     * @param    string $salt Salt
     *
     * @return    string
     */
    protected function hash_hkdf($algo = null, $ikm = null, $length = 0, $info = '', $salt = '')
    {
        // To match PHP's behavior as closely as possible (unusual
        // inputs and error messages included), we'll have to do
        // some weird stuff here ...
        if (func_num_args() < 2) {
            trigger_error(sprintf("hash_hkdf() expects at least 2 parameters, %d given", func_num_args()),
                E_USER_WARNING);

            return null;
        } elseif (func_num_args() > 5) {
            trigger_error(sprintf("hash_hkdf() expects at most 5 parameters, %d given", func_num_args()),
                E_USER_WARNING);

            return null;
        }
        foreach ([1 => 'algo', 2 => 'ikm', 4 => 'info', 5 => 'salt'] as $paramNumber => $paramName) {
            switch ($paramType = gettype($$paramName)) {
                case 'string':
                    break;
                case 'integer':
                case 'double':
                case 'NULL':
                    $$paramName = (string)$$paramName;
                    break;
                case 'boolean':
                    // Strangely, every scalar value BUT bool(true)
                    // can be safely casted ...
                    $$paramName = ($$paramName === true) ? '1' : '';
                    break;
                case 'object':
                    if (is_callable([$$paramName, '__toString'])) {
                        $$paramName = (string)$$paramName;
                        break;
                    }
                default:
                    trigger_error(sprintf("hash_hkdf() expects parameter %d to be string, %s given", $paramNumber,
                        $paramType), E_USER_WARNING);

                    return null;
            }
        }
        static $sizes;
        if (!isset($sizes)) {
            // Non-cryptographic hash functions are blacklisted,
            // so we might as well flip that to a whitelist and
            // include all the digest sizes here instead of
            // doing strlen(hash($algo, '')) on the fly ...
            //
            // Find the interesection of what's available on
            // PHP 7.1 and whatever version we're using.
            $sizes = array_intersect_key([
                'md2'         => 16,
                'md4'         => 16,
                'md5'         => 16,
                'sha1'        => 20,
                'sha224'      => 28,
                'sha256'      => 32,
                'sha384'      => 48,
                'sha512/224'  => 28,
                'sha512/256'  => 32,
                'sha512'      => 64,
                'sha3-224'    => 28,
                'sha3-256'    => 32,
                'sha3-384'    => 48,
                'sha3-512'    => 64,
                'ripemd128'   => 16,
                'ripemd160'   => 20,
                'ripemd256'   => 32,
                'ripemd320'   => 40,
                'whirlpool'   => 64,
                'tiger128,3'  => 16,
                'tiger160,3'  => 20,
                'tiger192,3'  => 24,
                'tiger128,4'  => 16,
                'tiger160,4'  => 20,
                'tiger192,4'  => 24,
                'snefru'      => 32,
                'snefru256'   => 32,
                'gost'        => 32,
                'gost-crypto' => 32,
                'haval128,3'  => 16,
                'haval160,3'  => 20,
                'haval192,3'  => 24,
                'haval224,3'  => 28,
                'haval256,3'  => 32,
                'haval128,4'  => 16,
                'haval160,4'  => 20,
                'haval192,4'  => 24,
                'haval224,4'  => 28,
                'haval256,4'  => 32,
                'haval128,5'  => 16,
                'haval160,5'  => 20,
                'haval192,5'  => 24,
                'haval224,5'  => 28,
                'haval256,5'  => 32,
            ], array_flip(hash_algos()));
            // PHP pre-5.4.0's output for Tiger hashes is in little-endian byte order - blacklist
            if (!defined('PHP_VERSION_ID') || PHP_VERSION_ID < 50400) {
                unset($sizes['tiger128,3'], $sizes['tiger160,3'], $sizes['tiger192,3'], $sizes['tiger128,4'], $sizes['tiger160,4'], $sizes['tiger192,4']);
            }
        }
        if (!isset($sizes[$algo])) {
            // Edge case ...
            // PHP does case-insensitive lookups and 'Md5', 'sHa1', etc. are accepted.
            // Still, we want to preserve the original input for the error message.
            if (!isset($sizes[strtolower($algo)])) {
                if (in_array(strtolower($algo), hash_algos(), true) && strncasecmp($algo, 'tiger1', 6) !== 0) {
                    trigger_error("hash_hkdf(): Non-cryptographic hashing algorithm: {$algo}", E_USER_WARNING);

                    return false;
                }
                trigger_error("hash_hkdf(): Unknown hashing algorithm: {$algo}", E_USER_WARNING);

                return false;
            }
            $algo = strtolower($algo);
        }
        if (!isset($ikm[0])) {
            trigger_error("hash_hkdf(): Input keying material cannot be empty", E_USER_WARNING);

            return false;
        }
        if (!is_int($length)) {
            // Integer casting rules so bizzare that we can't even cover all of them.
            // We'll try for just the simpler cases ...
            if (is_string($length) && isset($length[0]) && strspn($length, "0123456789", $length[0] === '-' ? 1 : 0)) {
                $length = (int)$length;
            } // For some reason, this next line executes without being marked as covered
            elseif (is_float($length)) // @codeCoverageIgnore
            {
                $length = (int)($length < 0 ? ceil($length) : floor($length));
            } elseif (!isset($length) || is_bool($length)) {
                $length = (int)$length;
            } else {
                trigger_error(sprintf("hash_hkdf() expects parameter 3 to be integer, %s given", gettype($length)),
                    E_USER_WARNING);

                return null;
            }
        }
        if ($length < 0) {
            trigger_error("hash_hkdf(): Length must be greater than or equal to 0: {$length}", E_USER_WARNING);

            return false;
        } elseif ($length > (255 * $sizes[$algo])) {
            trigger_error(sprintf("hash_hkdf(): Length must be less than or equal to %d: %d", 255 * $sizes[$algo],
                $length), E_USER_WARNING);

            return false;
        } elseif ($length === 0) {
            $length = $sizes[$algo];
        }
        isset($salt[0]) || $salt = str_repeat("\x0", $sizes[$algo]);
        $prk = hash_hmac($algo, $ikm, $salt, true);
        $okm = '';
        for ($keyBlock = '', $blockIndex = 1; !isset($okm[$length - 1]); $blockIndex++) {
            $keyBlock = hash_hmac($algo, $keyBlock . $info . chr($blockIndex), $prk, true);
            $okm .= $keyBlock;
        }

        // Byte-safety ...
        return defined('MB_OVERLOAD_STRING') ? mb_substr($okm, 0, $length, '8bit') : substr($okm, 0, $length);
    }

    /**
     * Workflow: Generate IV for the current session, encrypt the data using encryption key and
     * generated IV, write the session to database. Default session lifetime (usually defaults to 1440)
     * is taken directly from php.ini -> session.gc_maxlifetime.
     * @link http://php.net/manual/en/sessionhandlerinterface.write.php
     *
     * @param string $session_id The session id.
     * @param string $session_data
     * The encoded session data.
     * Please note sessions use an alternative serialization method (see php.ini)
     *
     * @return bool The return value (usually TRUE on success, FALSE on failure).
     * @throws \Exception
     * @since 5.4.0
     */
    public function write($session_id, $session_data)
    {
        /**
         * First generate the session initialisation vector (IV) and then
         * use it together with hashed encryption key to encrypt the data, then write the session to the database.
         * @important "IV" must have the same length as the cipher block size (128 bits, aka 16 bytes for AES256).
         * @var string of (psuedo) bytes (in binary form, you need to bin2hex the data if you want hexadecimal
         * representation.
         */
        $iv = openssl_random_pseudo_bytes(self::IV_LENGTH, $strong);

        // should NEVER happen for our cipher mode.
        if (!$strong) {
            throw new \Exception(sprintf('generated IV for the cipher mode "%s" is not strong enough',
                self::CIPHER_MODE));
        }

        // encrypt the data and immediately encode it so we can store it to the database
        $encodedEncryptedData = base64_encode($this->encrypt($session_data, $iv));
        unset($session_data); // cleaning

        $sql = $this->pdo->prepare("REPLACE INTO {$this->sessionsTableName} (session_id, modified, session_data, lifetime, iv) 
                                    VALUES (:session_id, NOW(), :session_data, :lifetime, :iv)");

        return $sql->execute([
            'session_id'   => $session_id,
            'session_data' => $encodedEncryptedData,
            'lifetime'     => ini_get('session.gc_maxlifetime'),
            'iv'           => $iv
        ]);
    }

    /**
     * Encrypts the data with given cipher.
     * adds HMAC checksum block of hashes to $ciphertext
     *
     * @param $plaintext
     * @param $iv string binary initialisation vector
     *
     * @return string (raw binary data)
     *         format: rightPartOfIntegrityHmac . ciphertext . leftPartOfIntegrityHmac;
     * @throws \Exception
     */
    protected function encrypt($plaintext, $iv)
    {

        // calculate the "integrity" hmac, use authenticationKey
        $integrityHashHmac = hash_hmac(self::HASH_ALGORITHM, $iv . $plaintext, $this->authenticationKey, true);

        // encrypt the raw data
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER_MODE, $this->hashedEncryptionKey, OPENSSL_RAW_DATA, $iv);

        unset($plaintext); // cleaning

        if (false === $ciphertext) {
            throw new \Exception(sprintf('data encryption failed in %s. error: %s', __METHOD__,
                openssl_error_string()));
        }

        // break the integrity hmac in hallf and glue ciphertext in betwean R and L
        $left = substr($integrityHashHmac, 0, self::HASH_HMAC_LENGTH / 2);
        $right = substr($integrityHashHmac, self::HASH_HMAC_LENGTH / 2);

        return $right . $ciphertext . $left;
    }

    /**
     * Read the session, decrypt the data with openssl cipher method, using session IV (initialisation vector)
     * and encryption key and return the decrypted data.
     * @link http://php.net/manual/en/sessionhandlerinterface.read.php
     *
     * @param string $session_id The session id to read data for.
     *
     * @return string
     * Returns an encoded string of the read data.
     * If nothing was read, it must return an empty string.
     * @since 5.4.0
     */
    public function read($session_id)
    {
        $sql = $this->pdo->prepare("SELECT session_data, iv
                                    FROM {$this->sessionsTableName}
                                    WHERE session_id = :session_id 
                                    AND (modified + INTERVAL lifetime SECOND) > NOW()");

        $executed = $sql->execute([
            'session_id' => $session_id,
        ]);

        if ($executed && $sql->rowCount()) {
            $session = $sql->fetchObject();

            return $this->decrypt(base64_decode($session->session_data), $session->iv);
        } else {
            return '';
        }
    }

    /**
     * Decrypts the data, extracts the header checksum,
     * re-calculates every hash and compares with data from checksum,
     * if everything goes well returns decrypted data.
     *
     * @param string $ciphertext raw string
     * @param string $iv in binary form
     *
     * @return string decrypted data
     * @throws \Exception
     */
    protected function decrypt($ciphertext, $iv)
    {
        // integrity check
        if (strlen($ciphertext) < self::IV_LENGTH) {
            throw new \Exception(sprintf('data integrity check failed in %s', __METHOD__));
        }

        // extract left and right side, glue them together to get Integrity hmac
        $right = substr($ciphertext, 0, self::HASH_HMAC_LENGTH / 2);
        $left = substr($ciphertext, -(self::HASH_HMAC_LENGTH / 2));

        // everything else in betwean is the real ciphertext
        $ciphertext = substr($ciphertext, self::HASH_HMAC_LENGTH / 2, -(self::HASH_HMAC_LENGTH / 2));

        // decrypt the data
        $plaintext = openssl_decrypt($ciphertext, self::CIPHER_MODE, $this->hashedEncryptionKey, OPENSSL_RAW_DATA, $iv);
        unset($ciphertext); // cleaning

        if (false === $plaintext) {
            throw new \Exception(sprintf('data decryption failed in %s. error: %s', __METHOD__,
                openssl_error_string()));
        }

        $extractedIntegrityHmac = $left . $right;
        // calculate integrity hmac and compare with extracted
        $calculatedIntegrityHmac = hash_hmac(self::HASH_ALGORITHM, $iv . $plaintext, $this->authenticationKey, true);
        if (!hash_equals($extractedIntegrityHmac, $calculatedIntegrityHmac)) {
            throw new \Exception('data hash hmac mismatch.');
        }

        return $plaintext;
    }

    /**
     * Destroy a session
     * @link http://php.net/manual/en/sessionhandlerinterface.destroy.php
     *
     * @param string $session_id The session ID being destroyed.
     *
     * @return bool
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     */
    public function destroy($session_id)
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionsTableName} WHERE session_id = :session_id")->execute([
            'session_id' => $session_id
        ]);
    }

    /**
     * Cleanup old sessions
     * @link http://php.net/manual/en/sessionhandlerinterface.gc.php
     *
     * @param int $maxlifetime
     * Sessions that have not updated for
     * the last maxlifetime seconds will be removed.
     *
     * @return bool
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     */
    public function gc($maxlifetime)
    {
        return $this->pdo->prepare("DELETE FROM {$this->sessionsTableName} WHERE (modified + INTERVAL lifetime SECOND) < NOW()")
                         ->execute();
    }

    /**
     * Initialize session
     * @link http://php.net/manual/en/sessionhandlerinterface.open.php
     *
     * @param string $save_path The path where to store/retrieve the session.
     * @param string $session_name The session name.
     *
     * @return bool
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     * @codeCoverageIgnore
     */
    public function open($save_path, $session_name)
    {
        return true;
    }

    /**
     * Close the session
     * @link http://php.net/manual/en/sessionhandlerinterface.close.php
     * @return bool
     * The return value (usually TRUE on success, FALSE on failure).
     * @since 5.4.0
     * @codeCoverageIgnore
     */
    public function close()
    {
        return true;
    }
}
