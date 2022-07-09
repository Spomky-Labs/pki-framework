<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Util;

use GMP;
use InvalidArgumentException;
use const PHP_INT_MAX;
use const PHP_INT_MIN;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Util\BigInt;
use function strval;
use ValueError;

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
        $int = new BigInt(gmp_strval(gmp_init(PHP_INT_MAX, 10)));
        static::assertEquals(PHP_INT_MAX, $int->intVal());
    }

    /**
     * @test
     */
    public function minInt()
    {
        $int = new BigInt(gmp_strval(gmp_init(PHP_INT_MIN, 10)));
        static::assertEquals(PHP_INT_MIN, $int->intVal());
    }

    /**
     * @test
     */
    public function overflow()
    {
        $int = new BigInt(gmp_strval(gmp_init(PHP_INT_MAX, 10) + 1));
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Integer overflow');
        $int->intVal();
    }

    /**
     * @test
     */
    public function underflow()
    {
        $int = new BigInt(gmp_strval(gmp_init(PHP_INT_MIN, 10) - 1));
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Integer underflow');
        $int->intVal();
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
    public function gmpObj()
    {
        $int = new BigInt(1);
        static::assertInstanceOf(GMP::class, $int->gmpObj());
    }

    /**
     * @requires PHP < 8.0
     *
     * @test
     */
    public function invalidNumberPrePHP8()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to convert');
        new BigInt('fail');
    }

    /**
     * @requires PHP >= 8.0
     *
     * @test
     */
    public function invalidNumberPHP8()
    {
        $this->expectException(ValueError::class);
        $this->expectExceptionMessage('not an integer');
        new BigInt('fail');
    }

    /**
     * @test
     */
    public function fromUnsignedOctets()
    {
        $int = BigInt::fromUnsignedOctets(hex2bin('ff'));
        static::assertEquals(255, $int->intVal());
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
        static::assertEquals(-128, $int->intVal());
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
