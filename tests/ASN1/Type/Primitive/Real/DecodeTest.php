<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Real;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Real;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @test
     */
    public function reservedBinaryEncodingFail()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Reserved REAL binary encoding base not supported');
        Real::fromDER(hex2bin('0902B000'));
    }

    /**
     * @test
     */
    public function binaryEncodingExponentLengthUnexpectedEnd()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding REAL exponent length');
        Real::fromDER(hex2bin('090183'));
    }

    /**
     * @test
     */
    public function binaryEncodingExponentUnexpectedEnd()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding REAL exponent');
        Real::fromDER(hex2bin('090180'));
    }

    /**
     * @test
     */
    public function binaryEncodingMantissaUnexpectedEnd()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding REAL mantissa');
        Real::fromDER(hex2bin('09028000'));
    }

    /**
     * @test
     */
    public function decimalEncodingUnsupportedForm()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unsupported decimal encoding form');
        Real::fromDER(hex2bin('09020400'));
    }

    /**
     * @test
     */
    public function specialEncodingTooLong()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('SpecialRealValue must have one content octet');
        Real::fromDER(hex2bin('09024000'));
    }

    /**
     * @test
     */
    public function specialEncodingInvalid()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid SpecialRealValue encoding');
        Real::fromDER(hex2bin('090142'));
    }

    /**
     * @test
     */
    public function longExponent()
    {
        $real = Real::fromDER(hex2bin('090783044000000001'));
        static::assertEquals('1073741824', $real->exponent()->base10());
    }
}
