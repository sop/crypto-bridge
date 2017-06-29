<?php
use Sop\CryptoBridge\Crypto;

class CryptoTest extends PHPUnit_Framework_TestCase
{
    public function testDefault()
    {
        $crypto = Crypto::getDefault();
        $this->assertInstanceOf(Crypto::class, $crypto);
    }
}
