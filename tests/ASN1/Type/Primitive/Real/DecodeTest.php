<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Real;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Real;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function reservedBinaryEncodingFail()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Reserved REAL binary encoding base not supported');
        Real::fromDER(hex2bin('0902B000'));
    }

    #[Test]
    public function binaryEncodingExponentLengthUnexpectedEnd()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding REAL exponent length');
        Real::fromDER(hex2bin('090183'));
    }

    #[Test]
    public function binaryEncodingExponentUnexpectedEnd()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding REAL exponent');
        Real::fromDER(hex2bin('090180'));
    }

    #[Test]
    public function binaryEncodingMantissaUnexpectedEnd()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding REAL mantissa');
        Real::fromDER(hex2bin('09028000'));
    }

    #[Test]
    public function decimalEncodingUnsupportedForm()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unsupported decimal encoding form');
        Real::fromDER(hex2bin('09020400'));
    }

    #[Test]
    public function specialEncodingTooLong()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('SpecialRealValue must have one content octet');
        Real::fromDER(hex2bin('09024000'));
    }

    #[Test]
    public function specialEncodingInvalid()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid SpecialRealValue encoding');
        Real::fromDER(hex2bin('090142'));
    }

    #[Test]
    public function longExponent()
    {
        $real = Real::fromDER(hex2bin('090783044000000001'));
        static::assertSame('1073741824', $real->exponent()->base10());
    }
}
