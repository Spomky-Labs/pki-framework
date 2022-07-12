<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Component;

use Brick\Math\BigInteger;
use function chr;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Element;

/**
 * @internal
 */
final class IdentifierEncodeTest extends TestCase
{
    /**
     * @test
     */
    public function universal()
    {
        $identifier = new Identifier(Identifier::CLASS_UNIVERSAL, Identifier::PRIMITIVE, Element::TYPE_BOOLEAN);
        static::assertEquals(chr(0b00000001), $identifier->toDER());
    }

    /**
     * @test
     */
    public function application()
    {
        $identifier = new Identifier(Identifier::CLASS_APPLICATION, Identifier::PRIMITIVE, Element::TYPE_BOOLEAN);
        static::assertEquals(chr(0b01000001), $identifier->toDER());
    }

    /**
     * @test
     */
    public function contextSpecific()
    {
        $identifier = new Identifier(
            Identifier::CLASS_CONTEXT_SPECIFIC,
            Identifier::PRIMITIVE,
            Element::TYPE_BOOLEAN
        );
        static::assertEquals(chr(0b10000001), $identifier->toDER());
    }

    /**
     * @test
     */
    public function private()
    {
        $identifier = new Identifier(Identifier::CLASS_PRIVATE, Identifier::PRIMITIVE, Element::TYPE_BOOLEAN);
        static::assertEquals(chr(0b11000001), $identifier->toDER());
    }

    /**
     * @test
     */
    public function constructed()
    {
        $identifier = new Identifier(Identifier::CLASS_UNIVERSAL, Identifier::CONSTRUCTED, Element::TYPE_SEQUENCE);
        static::assertEquals(chr(0b00110000), $identifier->toDER());
    }

    /**
     * @test
     */
    public function longTag()
    {
        $identifier = new Identifier(Identifier::CLASS_APPLICATION, Identifier::CONSTRUCTED, (0x7f << 7) + 0x7f);
        static::assertEquals(chr(0b01111111) . "\xff\x7f", $identifier->toDER());
    }

    /**
     * @test
     */
    public function hugeTag()
    {
        $num = gmp_init(str_repeat('1111111', 100) . '1111111', 2);
        $identifier = new Identifier(Identifier::CLASS_APPLICATION, Identifier::CONSTRUCTED, BigInteger::of($num));
        static::assertEquals(chr(0b01111111) . str_repeat("\xff", 100) . "\x7f", $identifier->toDER());
    }
}
