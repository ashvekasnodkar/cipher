<?php
namespace System\Security\Cryptography;

interface CipherInterface
{
    public function encrypt($data, $key);

    public function decrypt($data, $key);
}