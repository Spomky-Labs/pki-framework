<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Constructed\String;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\ConstructedString;
use Sop\ASN1\Type\Primitive\NullType;
use UnexpectedValueException;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    public function testDecodeDefinite()
    {
        $el = ConstructedString::fromDER(hex2bin('2400'));
        $this->assertInstanceOf(ConstructedString::class, $el);
        $this->assertFalse($el->hasIndefiniteLength());
    }

    public function testDecodeIndefinite()
    {
        $el = ConstructedString::fromDER(hex2bin('24800000'));
        $this->assertInstanceOf(ConstructedString::class, $el);
        $this->assertTrue($el->hasIndefiniteLength());
    }

    public function testInvalidCallingClass()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage(NullType::class . ' expected, got ' . ConstructedString::class);
        NullType::fromDER(hex2bin('2400'));
    }

    public function testDecodeBitString()
    {
        $el = ConstructedString::fromDER(hex2bin('23800301000000'));
        $this->assertInstanceOf(ConstructedString::class, $el);
        $this->assertTrue($el->has(0, Element::TYPE_BIT_STRING));
    }
}
