<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Component;

use Brick\Math\BigInteger;
use Brick\Math\Exception\IntegerOverflowException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use function chr;

/**
 * @internal
 */
final class IdentifierDecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $identifier = Identifier::fromDER("\x0");
        static::assertInstanceOf(Identifier::class, $identifier);
    }

    #[Test]
    public function universal()
    {
        $identifier = Identifier::fromDER(chr(0b00000000));
        static::assertTrue($identifier->isUniversal());
    }

    #[Test]
    public function application()
    {
        $identifier = Identifier::fromDER(chr(0b01000000));
        static::assertTrue($identifier->isApplication());
    }

    #[Test]
    public function contextSpecific()
    {
        $identifier = Identifier::fromDER(chr(0b10000000));
        static::assertTrue($identifier->isContextSpecific());
    }

    #[Test]
    public function private()
    {
        $identifier = Identifier::fromDER(chr(0b11000000));
        static::assertTrue($identifier->isPrivate());
    }

    #[Test]
    public function pC()
    {
        $identifier = Identifier::fromDER(chr(0b00000000));
        static::assertSame(Identifier::PRIMITIVE, $identifier->pc());
    }

    #[Test]
    public function primitive()
    {
        $identifier = Identifier::fromDER(chr(0b00000000));
        static::assertTrue($identifier->isPrimitive());
    }

    #[Test]
    public function constructed()
    {
        $identifier = Identifier::fromDER(chr(0b00100000));
        static::assertTrue($identifier->isConstructed());
    }

    #[Test]
    public function tag()
    {
        $identifier = Identifier::fromDER(chr(0b00001111));
        static::assertSame((string) 0b1111, $identifier->tag());
    }

    #[Test]
    public function intTag()
    {
        $identifier = Identifier::fromDER(chr(0b00001111));
        static::assertSame(0b1111, $identifier->intTag());
    }

    #[Test]
    public function longTag()
    {
        $identifier = Identifier::fromDER(chr(0b00011111) . "\x7f");
        static::assertSame((string) 0x7f, $identifier->tag());
    }

    #[Test]
    public function longTag2()
    {
        $identifier = Identifier::fromDER(chr(0b00011111) . "\xff\x7f");
        static::assertSame((string) ((0x7f << 7) + 0x7f), $identifier->tag());
    }

    #[Test]
    public function hugeTag()
    {
        $der = "\x1f" . str_repeat("\xff", 100) . "\x7f";
        $identifier = Identifier::fromDER($der);
        $num = BigInteger::fromBase(str_repeat('1111111', 100) . '1111111', 2);
        static::assertSame($num->toBase(10), $identifier->tag());
    }

    #[Test]
    public function hugeIntTagOverflow()
    {
        $der = "\x1f" . str_repeat("\xff", 100) . "\x7f";
        $this->expectException(IntegerOverflowException::class);
        Identifier::fromDER($der)->intTag();
    }

    #[Test]
    public function invalidOffset()
    {
        $offset = 1;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid offset');
        Identifier::fromDER("\x0", $offset);
    }

    #[Test]
    public function unexpectedTagEnd()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding long form identifier');
        Identifier::fromDER("\x1f\xff");
    }
}
