<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoBridge\Unit\Crypto;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoBridge\Crypto;

/**
 * @internal
 */
final class CryptoTest extends TestCase
{
    /**
     * @test
     */
    public function default()
    {
        $crypto = Crypto::getDefault();
        static::assertInstanceOf(Crypto::class, $crypto);
    }
}
