<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoBridge\Crypto;

/**
 * @internal
 */
class CryptoTest extends TestCase
{
    public function testDefault()
    {
        $crypto = Crypto::getDefault();
        $this->assertInstanceOf(Crypto::class, $crypto);
    }
}
