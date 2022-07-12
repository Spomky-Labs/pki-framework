<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Util;

use Brick\Math\BigInteger;
use Brick\Math\Exception\IntegerOverflowException;
use InvalidArgumentException;
use const PHP_INT_MAX;
use const PHP_INT_MIN;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Util\BigInt;
use function strval;

/**
 * @internal
 */
final class BigIntTest extends TestCase
{
    /**
     * @test
     */
    public function maxInt()
    {
        $int = new BigInt(BigInteger::of(PHP_INT_MAX));
        static::assertEquals(PHP_INT_MAX, $int->toInt());
    }

    /**
     * @test
     */
    public function minInt()
    {
        $int = new BigInt(BigInteger::of(PHP_INT_MIN));
        static::assertEquals(PHP_INT_MIN, $int->toInt());
    }

    /**
     * @test
     */
    public function overflow()
    {
        $int = new BigInt(BigInteger::of(PHP_INT_MAX)->plus(1));
        $this->expectException(IntegerOverflowException::class);
        $int->toInt();
    }

    /**
     * @test
     */
    public function underflow()
    {
        $int = new BigInt(BigInteger::of(PHP_INT_MIN)->minus(1));
        $this->expectException(IntegerOverflowException::class);
        $int->toInt();
    }

    /**
     * @test
     */
    public function toStringMethod()
    {
        $int = new BigInt(1);
        static::assertSame('1', strval($int));
    }

    /**
     * @test
     */
    public function getBigIntegerObject()
    {
        $int = new BigInt(1);
        static::assertInstanceOf(BigInteger::class, $int->getValue());
    }

    /**
     * @test
     */
    public function invalidNumber()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to convert');
        new BigInt('fail');
    }

    /**
     * @test
     */
    public function fromUnsignedOctets()
    {
        $int = BigInt::fromUnsignedOctets(hex2bin('ff'));
        static::assertEquals(255, $int->toInt());
    }

    /**
     * @test
     */
    public function fromUnsignedOctetsEmpty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Empty octets');
        BigInt::fromUnsignedOctets('');
    }

    /**
     * @test
     */
    public function fromSignedOctets()
    {
        $int = BigInt::fromSignedOctets(hex2bin('80'));
        static::assertEquals(-128, $int->toInt());
    }

    /**
     * @test
     */
    public function fromSignedOctetsEmpty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Empty octets');
        BigInt::fromSignedOctets('');
    }

    /**
     * @test
     */
    public function toUnsignedOctets()
    {
        $int = new BigInt(255);
        static::assertEquals(hex2bin('ff'), $int->unsignedOctets());
    }

    /**
     * @test
     */
    public function toSignedPositiveOctets()
    {
        $int = new BigInt(127);
        static::assertEquals(hex2bin('7f'), $int->signedOctets());
    }

    /**
     * @test
     */
    public function toSignedPositiveOctetsPrepend()
    {
        $int = new BigInt(128);
        static::assertEquals(hex2bin('0080'), $int->signedOctets());
    }

    /**
     * @test
     */
    public function toSignedNegativeOctets()
    {
        $int = new BigInt(-128);
        static::assertEquals(hex2bin('80'), $int->signedOctets());
    }

    /**
     * @test
     */
    public function toSignedNegativeOctetsPrepend()
    {
        $int = new BigInt(-32769);
        static::assertEquals(hex2bin('ff7fff'), $int->signedOctets());
    }

    /**
     * @test
     */
    public function toSignedZeroOctets()
    {
        $int = new BigInt(0);
        static::assertEquals(hex2bin('00'), $int->signedOctets());
    }
}
