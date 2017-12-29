<?php
namespace System\Security\Cryptography;

class OpensslCipher implements CipherInterface
{
    private $algorithm;
    private $mode;
    private $iv;
    
    public function __construct($algorithm, $mode, $iv) {
        $this->algorithm = $algorithm ? $algorithm : 'BF-ECB';
        $this->mode = $mode ? $mode : OPENSSL_RAW_DATA | OPENSSL_NO_PADDING;
        
        if (!$iv) {
            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->algorithm));
        }
        
        $this->iv = $iv;        
    }
    
    public function encrypt($data, $key)
    {
        if (!$key) {
            return false;
        }
        
        $l = strlen($key);

        if ($l < 16) {
            $key = str_repeat($key, ceil(16 / $l));
        }

        if ($m = strlen($data) % 8) {
            $data .= str_repeat("\x00", 8 - $m);
        }

        $val = openssl_encrypt($data, $this->algorithm, $key, $this->mode, $this->iv);
        
        return $val;
    }

    public function decrypt($data, $key) {
        if (!$key) {
            return false;
        }
        
        $l = strlen($key);

        if ($l < 16) {
            $key = str_repeat($key, ceil(16 / $l));
        }

        $val = openssl_decrypt($data, $this->algorithm, $key, $this->mode, $this->iv);
        
        if ($val) {
            $val = rtrim($val, "\0");
        }
        
        return $val;
    }
}