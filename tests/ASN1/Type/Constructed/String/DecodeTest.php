<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\String;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\ConstructedString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use UnexpectedValueException;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function decodeDefinite()
    {
        $el = ConstructedString::fromDER(hex2bin('2400'));
        static::assertInstanceOf(ConstructedString::class, $el);
        static::assertFalse($el->hasIndefiniteLength());
    }

    #[Test]
    public function decodeIndefinite()
    {
        $el = ConstructedString::fromDER(hex2bin('24800000'));
        static::assertInstanceOf(ConstructedString::class, $el);
        static::assertTrue($el->hasIndefiniteLength());
    }

    #[Test]
    public function invalidCallingClass()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage(NullType::class . ' expected, got ' . ConstructedString::class);
        NullType::fromDER(hex2bin('2400'));
    }

    #[Test]
    public function decodeBitString()
    {
        $el = ConstructedString::fromDER(hex2bin('23800301000000'));
        static::assertInstanceOf(ConstructedString::class, $el);
        static::assertTrue($el->has(0, Element::TYPE_BIT_STRING));
    }
}
