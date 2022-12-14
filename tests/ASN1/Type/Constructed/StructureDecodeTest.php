<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed;

use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Structure;
use SpomkyLabs\Pki\ASN1\Type\Tagged\DERTaggedType;

/**
 * @internal
 */
final class StructureDecodeTest extends TestCase
{
    /**
     * Test too short length.
     */
    #[Test]
    public function tooShort()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Structure\'s content overflows length');
        Structure::fromDER("\x30\x1\x5\x0");
    }

    /**
     * Test too long length.
     */
    #[Test]
    public function tooLong()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Length 3 overflows data, 2 bytes left');
        Structure::fromDER("\x30\x3\x5\x0");
    }

    /**
     * Test when structure doesn't have constructed flag.
     */
    #[Test]
    public function notConstructed()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Structured element must have constructed bit set');
        Structure::fromDER("\x10\x0");
    }

    #[Test]
    public function implicitlyTaggedExists()
    {
        // null, tag 0, null
        $set = Set::fromDER("\x31\x6\x5\x0\x80\x0\x5\x0");
        static::assertTrue($set->hasTagged(0));
    }

    #[Test]
    public function implicitlyTaggedFetch()
    {
        // null, tag 1, null
        $set = Set::fromDER("\x31\x6\x5\x0\x81\x0\x5\x0");
        static::assertInstanceOf(DERTaggedType::class, $set->getTagged(1));
    }

    #[Test]
    public function explicitlyTaggedExists()
    {
        // null, tag 0 (null), null
        $set = Set::fromDER("\x31\x8\x5\x0\xa0\x2\x5\x0\x5\x0");
        static::assertTrue($set->hasTagged(0));
    }

    #[Test]
    public function explicitlyTaggedFetch()
    {
        // null, tag 1 (null), null
        $set = Set::fromDER("\x31\x8\x5\x0\xa1\x2\x5\x0\x5\x0");
        static::assertInstanceOf(DERTaggedType::class, $set->getTagged(1));
        static::assertInstanceOf(NullType::class, $set->getTagged(1)->expectExplicit()->explicit()->asNull());
    }

    #[Test]
    public function invalidTag()
    {
        // null, tag 0, null
        $set = Set::fromDER("\x31\x6\x5\x0\x80\x0\x5\x0");
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('No tagged element for tag 1');
        $set->getTagged(1);
    }

    #[Test]
    public function indefinite()
    {
        $seq = Sequence::fromDER(hex2bin('30800201010000'));
        static::assertInstanceOf(Sequence::class, $seq);
    }

    #[Test]
    public function indefiniteUnexpectedEnd()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding indefinite length structure');
        Sequence::fromDER(hex2bin('3080020101'));
    }
}
