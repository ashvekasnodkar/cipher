<?php
use System\Security\Cryptography\Cipher;

require_once 'app/start.php';

$originalString = 'my secret message';
$key = 'letskeepitsecret';

$cipher = Cipher::create();
$encryptResult = $cipher->encrypt($originalString, $key);
$decryptResult = $cipher->decrypt($encryptResult, $key);

echo "Encryption/Decryption using default cipher (Openssl):<br/>";
echo "Original String: $originalString<br/>";
echo "Encrypt Result: $encryptResult<br/>";
echo "Decrypt Result: $decryptResult<br/><br/>";

$cipher = Cipher::create('mcrypt');
$encryptResult = $cipher->encrypt($originalString, $key);
$decryptResult = $cipher->decrypt($encryptResult, $key);

echo "Encryption/Decryption using Mcrypt:<br/>";
echo "Original String: $originalString<br/>";
echo "Encrypt Result: $encryptResult<br/>";
echo "Decrypt Result: $decryptResult<br/><br/>";

$cipher = Cipher::create('openssl');
$encryptResult = $cipher->encrypt($originalString, $key);
$decryptResult = $cipher->decrypt($encryptResult, $key);

echo nl2br("Encryption/Decryption using Openssl:<br/>");
echo "Original String: $originalString<br/>";
echo "Encrypt Result: $encryptResult<br/>";
echo "Decrypt Result: $decryptResult";