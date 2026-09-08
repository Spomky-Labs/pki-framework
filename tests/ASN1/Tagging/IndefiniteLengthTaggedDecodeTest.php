<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use function chr;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ContextSpecificType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;

/**
 * An indefinite length states no size up front, so the decoder has to walk the content to find the matching
 * end-of-contents. It did not: the offset stayed just after the length octets and the content length came out
 * as -2, which spilled the element's content into the enclosing structure as siblings.
 *
 * @internal
 */
final class IndefiniteLengthTaggedDecodeTest extends TestCase
{
    /**
     * [0] with indefinite length, holding INTEGER 1.
     *
     * @var string
     */
    private const TAGGED = 'a0800201010000';

    #[Test]
    public function decodingConsumesTheWholeElement(): void
    {
        $der = hex2bin(self::TAGGED);
        $offset = 0;
        TaggedType::fromDER($der, $offset);

        static::assertSame(mb_strlen($der, '8bit'), $offset);
    }

    #[Test]
    public function contentDoesNotSpillIntoTheEnclosingStructure(): void
    {
        // SEQUENCE { [0] { INTEGER 1 }, INTEGER 2 } holds two elements, not four.
        $seq = Element::fromDER(self::wrapInSequence(hex2bin(self::TAGGED) . hex2bin('020102')));

        static::assertCount(2, $seq);
        static::assertInstanceOf(ContextSpecificType::class, $seq->at(0)->asElement());
        static::assertInstanceOf(Integer::class, $seq->at(1)->asElement());
        static::assertSame(2, $seq->at(1)->asInteger()->intNumber());
    }

    #[Test]
    public function theTaggedContentIsStillReadable(): void
    {
        $seq = Element::fromDER(self::wrapInSequence(hex2bin(self::TAGGED) . hex2bin('020102')));

        static::assertSame(1, $seq->at(0)->asTagged()->asExplicit()->asInteger()->intNumber());
    }

    #[Test]
    public function roundTripIsPreserved(): void
    {
        $der = hex2bin(self::TAGGED);

        static::assertSame($der, TaggedType::fromDER($der)->toDER());
    }

    #[Test]
    public function nestedIndefiniteLengthsAreHandled(): void
    {
        // [0] { [1] { INTEGER 1 } }
        $der = hex2bin('a080a1800201010000') . "\x00\x00";
        $offset = 0;
        $el = TaggedType::fromDER($der, $offset);

        static::assertSame(mb_strlen($der, '8bit'), $offset);
        static::assertSame(1, $el->asExplicit()->asTagged()->asExplicit()->asInteger()->intNumber());
    }

    #[Test]
    public function severalIndefiniteLengthSiblingsAreSeparated(): void
    {
        $seq = Element::fromDER(self::wrapInSequence(hex2bin(self::TAGGED) . hex2bin(self::TAGGED)));

        static::assertCount(2, $seq);
        static::assertSame(1, $seq->at(0)->asTagged()->asExplicit()->asInteger()->intNumber());
        static::assertSame(1, $seq->at(1)->asTagged()->asExplicit()->asInteger()->intNumber());
    }

    #[Test]
    public function aMissingEndOfContentsIsRejected(): void
    {
        // Without a terminating EOC the decoder must stop rather than run past the end of the buffer.
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data');
        TaggedType::fromDER(hex2bin('a080020101'));
    }

    private static function wrapInSequence(string $content): string
    {
        return "\x30" . chr(mb_strlen($content, '8bit')) . $content;
    }
}
