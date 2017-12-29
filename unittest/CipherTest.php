<?php
use System\Security\Cryptography\Cipher;

require_once __DIR__ . '\..\vendor\autoload.php';

class CipherTest extends PHPUnit_Framework_TestCase
{
    public function testEncryptDecrypt()
    {
        $originalString = 'my secret message\0';
        $key = 'letskeepitsecret';

        $cipher = Cipher::create();

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertEquals($originalString, $decryptResult);
    }
    
    public function testEncryptDecryptwithEmptyKey()
    {
        $originalString = 'my secret message';
        $key = '';

        $cipher = Cipher::create();

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertFalse($decryptResult);
    }
    
    public function testEncryptDecryptwithEmptyData()
    {
        $originalString = '';
        $key = 'letskeepitsecret';

        $cipher = Cipher::create();

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertEquals($originalString, $decryptResult);
    }
    
    public function testOpensslEncryptDecrypt()
    {
        $originalString = 'my secret message';
        $key = 'letskeepitsecret';

        $cipher = Cipher::create('openssl');

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertEquals($originalString, $decryptResult);
    }
    
    public function testOpensslEncryptDecryptwithEmptyKey()
    {
        $originalString = 'my secret message';
        $key = '';

        $cipher = Cipher::create('openssl');

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertFalse($decryptResult);
    }
    
    public function testOpensslEncryptDecryptwithEmptyData()
    {
        $originalString = '';
        $key = 'letskeepitsecret';

        $cipher = Cipher::create('openssl');

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertEquals($originalString, $decryptResult);
    }
    
    public function testMcryptEncryptDecrypt()
    {
        $originalString = 'my secret message';
        $key = 'letskeepitsecret';

        $cipher = Cipher::create('mcrypt');

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertEquals($originalString, $decryptResult);
    }
    
    public function testMcryptEncryptDecryptwithEmptyKey()
    {
        $originalString = 'my secret message';
        $key = '';

        $cipher = Cipher::create('mcrypt');

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertFalse($decryptResult);
    }
    
    public function testMcryptEncryptDecryptwithEmptyData()
    {
        $originalString = '';
        $key = 'letskeepitsecret';

        $cipher = Cipher::create('mcrypt');

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertEquals($originalString, $decryptResult);
    }
    
    public function testInvalidCipherEncryptDecrypt()
    {
        $originalString = 'my secret message';
        $key = 'letskeepitsecret';

        $cipher = Cipher::create('test1234');

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertEquals($originalString, $decryptResult);
    }
    
    public function testInvalidCipherEncryptDecryptwithEmptyKey()
    {
        $originalString = 'my secret message';
        $key = '';

        $cipher = Cipher::create('test1234');

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertFalse($decryptResult);
    }
    
    public function testInvalidCipherEncryptDecryptwithEmptyData()
    {
        $originalString = '';
        $key = 'letskeepitsecret';

        $cipher = Cipher::create('test1234');

        $encryptResult = $cipher->encrypt($originalString, $key);
        
        $decryptResult = $cipher->decrypt($encryptResult, $key);

        $this->assertEquals($originalString, $decryptResult);
    }
}