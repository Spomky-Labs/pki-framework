<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Component;

use function chr;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Exception\DecodeException;

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
        $this->assertInstanceOf(Identifier::class, $identifier);
    }

    /**
     * @test
     */
    public function universal()
    {
        $identifier = Identifier::fromDER(chr(0b00000000));
        $this->assertTrue($identifier->isUniversal());
    }

    /**
     * @test
     */
    public function application()
    {
        $identifier = Identifier::fromDER(chr(0b01000000));
        $this->assertTrue($identifier->isApplication());
    }

    /**
     * @test
     */
    public function contextSpecific()
    {
        $identifier = Identifier::fromDER(chr(0b10000000));
        $this->assertTrue($identifier->isContextSpecific());
    }

    /**
     * @test
     */
    public function private()
    {
        $identifier = Identifier::fromDER(chr(0b11000000));
        $this->assertTrue($identifier->isPrivate());
    }

    /**
     * @test
     */
    public function pC()
    {
        $identifier = Identifier::fromDER(chr(0b00000000));
        $this->assertEquals(Identifier::PRIMITIVE, $identifier->pc());
    }

    /**
     * @test
     */
    public function primitive()
    {
        $identifier = Identifier::fromDER(chr(0b00000000));
        $this->assertTrue($identifier->isPrimitive());
    }

    /**
     * @test
     */
    public function constructed()
    {
        $identifier = Identifier::fromDER(chr(0b00100000));
        $this->assertTrue($identifier->isConstructed());
    }

    /**
     * @test
     */
    public function tag()
    {
        $identifier = Identifier::fromDER(chr(0b00001111));
        $this->assertEquals(0b1111, $identifier->tag());
    }

    /**
     * @test
     */
    public function intTag()
    {
        $identifier = Identifier::fromDER(chr(0b00001111));
        $this->assertEquals(0b1111, $identifier->intTag());
    }

    /**
     * @test
     */
    public function longTag()
    {
        $identifier = Identifier::fromDER(chr(0b00011111) . "\x7f");
        $this->assertEquals(0x7f, $identifier->tag());
    }

    /**
     * @test
     */
    public function longTag2()
    {
        $identifier = Identifier::fromDER(chr(0b00011111) . "\xff\x7f");
        $this->assertEquals((0x7f << 7) + 0x7f, $identifier->tag());
    }

    /**
     * @test
     */
    public function hugeTag()
    {
        $der = "\x1f" . str_repeat("\xff", 100) . "\x7f";
        $identifier = Identifier::fromDER($der);
        $num = gmp_init(str_repeat('1111111', 100) . '1111111', 2);
        $this->assertEquals(gmp_strval($num, 10), $identifier->tag());
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
