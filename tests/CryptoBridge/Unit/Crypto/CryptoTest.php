<?php

declare(strict_types=1);

namespace Sop\Test\CryptoBridge\Unit\Crypto;

use PHPUnit\Framework\TestCase;
use Sop\CryptoBridge\Crypto;

/**
 * @internal
 */
final class CryptoTest extends TestCase
{
    public function testDefault()
    {
        $crypto = Crypto::getDefault();
        $this->assertInstanceOf(Crypto::class, $crypto);
    }
}
