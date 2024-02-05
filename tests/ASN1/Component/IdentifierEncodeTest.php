<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Component;

use Brick\Math\BigInteger;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Element;
use function chr;

/**
 * @internal
 */
final class IdentifierEncodeTest extends TestCase
{
    #[Test]
    public function universal()
    {
        $identifier = Identifier::create(Identifier::CLASS_UNIVERSAL, Identifier::PRIMITIVE, Element::TYPE_BOOLEAN);
        static::assertSame(chr(0b00000001), $identifier->toDER());
    }

    #[Test]
    public function application()
    {
        $identifier = Identifier::create(Identifier::CLASS_APPLICATION, Identifier::PRIMITIVE, Element::TYPE_BOOLEAN);
        static::assertSame(chr(0b01000001), $identifier->toDER());
    }

    #[Test]
    public function contextSpecific()
    {
        $identifier = Identifier::create(
            Identifier::CLASS_CONTEXT_SPECIFIC,
            Identifier::PRIMITIVE,
            Element::TYPE_BOOLEAN
        );
        static::assertSame(chr(0b10000001), $identifier->toDER());
    }

    #[Test]
    public function private()
    {
        $identifier = Identifier::create(Identifier::CLASS_PRIVATE, Identifier::PRIMITIVE, Element::TYPE_BOOLEAN);
        static::assertSame(chr(0b11000001), $identifier->toDER());
    }

    #[Test]
    public function constructed()
    {
        $identifier = Identifier::create(Identifier::CLASS_UNIVERSAL, Identifier::CONSTRUCTED, Element::TYPE_SEQUENCE);
        static::assertSame(chr(0b00110000), $identifier->toDER());
    }

    #[Test]
    public function longTag()
    {
        $identifier = Identifier::create(Identifier::CLASS_APPLICATION, Identifier::CONSTRUCTED, (0x7f << 7) + 0x7f);
        static::assertSame(chr(0b01111111) . "\xff\x7f", $identifier->toDER());
    }

    #[Test]
    public function hugeTag()
    {
        $num = BigInteger::fromBase(str_repeat('1111111', 100) . '1111111', 2);
        $identifier = Identifier::create(Identifier::CLASS_APPLICATION, Identifier::CONSTRUCTED, $num);
        static::assertSame(chr(0b01111111) . str_repeat("\xff", 100) . "\x7f", $identifier->toDER());
    }
}
