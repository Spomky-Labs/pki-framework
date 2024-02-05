<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Util;

use Brick\Math\BigInteger;
use Brick\Math\Exception\IntegerOverflowException;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Util\BigInt;
use function strval;
use const PHP_INT_MAX;
use const PHP_INT_MIN;

/**
 * @internal
 */
final class BigIntTest extends TestCase
{
    #[Test]
    public function maxInt()
    {
        $int = BigInt::create(BigInteger::of(PHP_INT_MAX));
        static::assertEquals(PHP_INT_MAX, $int->toInt());
    }

    #[Test]
    public function minInt()
    {
        $int = BigInt::create(BigInteger::of(PHP_INT_MIN));
        static::assertEquals(PHP_INT_MIN, $int->toInt());
    }

    #[Test]
    public function overflow()
    {
        $int = BigInt::create(BigInteger::of(PHP_INT_MAX)->plus(1));
        $this->expectException(IntegerOverflowException::class);
        $int->toInt();
    }

    #[Test]
    public function underflow()
    {
        $int = BigInt::create(BigInteger::of(PHP_INT_MIN)->minus(1));
        $this->expectException(IntegerOverflowException::class);
        $int->toInt();
    }

    #[Test]
    public function toStringMethod()
    {
        $int = BigInt::create(1);
        static::assertSame('1', strval($int));
    }

    #[Test]
    public function getBigIntegerObject()
    {
        $int = BigInt::create(1);
        static::assertInstanceOf(BigInteger::class, $int->getValue());
    }

    #[Test]
    public function invalidNumber()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to convert');
        BigInt::create('fail');
    }

    #[Test]
    public function fromUnsignedOctets()
    {
        $int = BigInt::fromUnsignedOctets(hex2bin('ff'));
        static::assertSame(255, $int->toInt());
    }

    #[Test]
    public function fromUnsignedOctetsEmpty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Empty octets');
        BigInt::fromUnsignedOctets('');
    }

    #[Test]
    public function fromSignedOctets()
    {
        $int = BigInt::fromSignedOctets(hex2bin('80'));
        static::assertSame(-128, $int->toInt());
    }

    #[Test]
    public function fromSignedOctetsEmpty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Empty octets');
        BigInt::fromSignedOctets('');
    }

    #[Test]
    public function toUnsignedOctets()
    {
        $int = BigInt::create(255);
        static::assertEquals(hex2bin('ff'), $int->unsignedOctets());
    }

    #[Test]
    public function toSignedPositiveOctets()
    {
        $int = BigInt::create(127);
        static::assertEquals(hex2bin('7f'), $int->signedOctets());
    }

    #[Test]
    public function toSignedPositiveOctetsPrepend()
    {
        $int = BigInt::create(128);
        static::assertEquals(hex2bin('0080'), $int->signedOctets());
    }

    #[Test]
    public function toSignedNegativeOctets()
    {
        $int = BigInt::create(-128);
        static::assertEquals(hex2bin('80'), $int->signedOctets());
    }

    #[Test]
    public function toSignedNegativeOctetsPrepend()
    {
        $int = BigInt::create(-32769);
        static::assertEquals(hex2bin('ff7fff'), $int->signedOctets());
    }

    #[Test]
    public function toSignedZeroOctets()
    {
        $int = BigInt::create(0);
        static::assertEquals(hex2bin('00'), $int->signedOctets());
    }
}
