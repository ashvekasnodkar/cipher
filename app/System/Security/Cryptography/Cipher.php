<?php
namespace System\Security\Cryptography;

class Cipher 
{
    public static function create($type = 'openssl', $algorithm = null, $mode = null, $iv = null)
    {
        if (strcasecmp($type, 'mcrypt') == 0) {
            return new McryptCipher($algorithm, $mode, $iv);
        }

        return new OpensslCipher($algorithm, $mode, $iv);
    }
}
