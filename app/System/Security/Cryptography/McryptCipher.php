<?php
namespace System\Security\Cryptography;

class McryptCipher implements CipherInterface 
{
    private $algorithm;
    private $mode;
    private $iv;

    public function __construct($algorithm, $mode, $iv) {
        $this->algorithm = $algorithm ? $algorithm : MCRYPT_BLOWFISH;
        $this->mode = $mode ? $mode : MCRYPT_MODE_ECB;
        
        if (!$iv) {
            $iv_length = mcrypt_get_iv_size($this->algorithm, $this->mode);
            $iv = mcrypt_create_iv( $iv_length, MCRYPT_RAND );
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

        $val = mcrypt_encrypt($this->algorithm, $key, $data, $this->mode, $this->iv);

        return $val;
    }

    public function decrypt($data, $key)
    {
        if (!$key) {
            return false;
        }
        
        $l = strlen($key);

        if ($l < 16) {
            $key = str_repeat($key, ceil(16 / $l));
        }

        $val = mcrypt_decrypt($this->algorithm, $key, $data, $this->mode, $this->iv);
        
        if ($val) {
            $val = rtrim($val, "\0");
        }

        return $val;
    }
}