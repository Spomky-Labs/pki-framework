<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Component;

use function chr;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;

/**
 * @internal
 */
final class IdentifierDecodeTest extends TestCase
{
    /**
     * @test
     */
    public function type()
    {
        $identifier = Identifier::fromDER("\x0");
        static::assertInstanceOf(Identifier::class, $identifier);
    }

    /**
     * @test
     */
    public function universal()
    {
        $identifier = Identifier::fromDER(chr(0b00000000));
        static::assertTrue($identifier->isUniversal());
    }

    /**
     * @test
     */
    public function application()
    {
        $identifier = Identifier::fromDER(chr(0b01000000));
        static::assertTrue($identifier->isApplication());
    }

    /**
     * @test
     */
    public function contextSpecific()
    {
        $identifier = Identifier::fromDER(chr(0b10000000));
        static::assertTrue($identifier->isContextSpecific());
    }

    /**
     * @test
     */
    public function private()
    {
        $identifier = Identifier::fromDER(chr(0b11000000));
        static::assertTrue($identifier->isPrivate());
    }

    /**
     * @test
     */
    public function pC()
    {
        $identifier = Identifier::fromDER(chr(0b00000000));
        static::assertEquals(Identifier::PRIMITIVE, $identifier->pc());
    }

    /**
     * @test
     */
    public function primitive()
    {
        $identifier = Identifier::fromDER(chr(0b00000000));
        static::assertTrue($identifier->isPrimitive());
    }

    /**
     * @test
     */
    public function constructed()
    {
        $identifier = Identifier::fromDER(chr(0b00100000));
        static::assertTrue($identifier->isConstructed());
    }

    /**
     * @test
     */
    public function tag()
    {
        $identifier = Identifier::fromDER(chr(0b00001111));
        static::assertEquals(0b1111, $identifier->tag());
    }

    /**
     * @test
     */
    public function intTag()
    {
        $identifier = Identifier::fromDER(chr(0b00001111));
        static::assertEquals(0b1111, $identifier->intTag());
    }

    /**
     * @test
     */
    public function longTag()
    {
        $identifier = Identifier::fromDER(chr(0b00011111) . "\x7f");
        static::assertEquals(0x7f, $identifier->tag());
    }

    /**
     * @test
     */
    public function longTag2()
    {
        $identifier = Identifier::fromDER(chr(0b00011111) . "\xff\x7f");
        static::assertEquals((0x7f << 7) + 0x7f, $identifier->tag());
    }

    /**
     * @test
     */
    public function hugeTag()
    {
        $der = "\x1f" . str_repeat("\xff", 100) . "\x7f";
        $identifier = Identifier::fromDER($der);
        $num = gmp_init(str_repeat('1111111', 100) . '1111111', 2);
        static::assertEquals(gmp_strval($num, 10), $identifier->tag());
    }

    /**
     * @test
     */
    public function hugeIntTagOverflow()
    {
        $der = "\x1f" . str_repeat("\xff", 100) . "\x7f";
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Integer overflow');
        Identifier::fromDER($der)->intTag();
    }

    /**
     * @test
     */
    public function invalidOffset()
    {
        $offset = 1;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid offset');
        Identifier::fromDER("\x0", $offset);
    }

    /**
     * @test
     */
    public function unexpectedTagEnd()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding long form identifier');
        Identifier::fromDER("\x1f\xff");
    }
}
