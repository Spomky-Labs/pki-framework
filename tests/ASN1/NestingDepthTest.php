<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1;

use function base64_encode;
use function chr;
use function chunk_split;
use InvalidArgumentException;
use function mb_strlen;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use function str_repeat;

/**
 * @internal
 */
final class NestingDepthTest extends TestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();
        Element::setMaxNestingDepth(Element::DEFAULT_MAX_NESTING_DEPTH);
    }

    #[Test]
    public function defaultMaxNestingDepth(): void
    {
        static::assertSame(Element::DEFAULT_MAX_NESTING_DEPTH, Element::maxNestingDepth());
    }

    #[Test]
    public function nestingWithinLimitIsDecoded(): void
    {
        $el = Element::fromDER(self::definiteLengthSequences(Element::DEFAULT_MAX_NESTING_DEPTH));
        static::assertTrue($el->isType(Element::TYPE_SEQUENCE));
    }

    /**
     * The end-of-contents marker of an indefinite length encoding is an element of its own, hence it takes a level.
     */
    #[Test]
    public function indefiniteLengthNestingWithinLimitIsDecoded(): void
    {
        $el = Element::fromDER(self::indefiniteLengthSequences(Element::DEFAULT_MAX_NESTING_DEPTH - 1));
        static::assertTrue($el->isType(Element::TYPE_SEQUENCE));
    }

    #[Test]
    public function deeplyNestedIndefiniteLengthStructureIsRejected(): void
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Maximum allowed nesting depth of 64 exceeded while decoding.');
        Element::fromDER(self::indefiniteLengthSequences(Element::DEFAULT_MAX_NESTING_DEPTH + 1));
    }

    #[Test]
    public function deeplyNestedDefiniteLengthStructureIsRejected(): void
    {
        $this->expectException(DecodeException::class);
        Element::fromDER(self::definiteLengthSequences(Element::DEFAULT_MAX_NESTING_DEPTH + 1));
    }

    /**
     * A structure large enough to exhaust the C stack must be rejected before the recursion goes too deep.
     */
    #[Test]
    public function stackExhaustingStructureIsRejected(): void
    {
        $this->expectException(DecodeException::class);
        Element::fromDER(self::indefiniteLengthSequences(100000));
    }

    #[Test]
    public function stackExhaustingCertificateIsRejected(): void
    {
        $der = self::indefiniteLengthSequences(100000);
        $pem = PEM::fromString(
            "-----BEGIN CERTIFICATE-----\n" . chunk_split(
                base64_encode($der),
                64,
                "\n"
            ) . "-----END CERTIFICATE-----\n"
        );
        $this->expectException(DecodeException::class);
        Certificate::fromPEM($pem);
    }

    #[Test]
    public function maxNestingDepthIsConfigurable(): void
    {
        Element::setMaxNestingDepth(2);
        static::assertSame(2, Element::maxNestingDepth());
        $el = Element::fromDER(self::definiteLengthSequences(2));
        static::assertTrue($el->isType(Element::TYPE_SEQUENCE));
        $this->expectException(DecodeException::class);
        Element::fromDER(self::definiteLengthSequences(3));
    }

    #[Test]
    public function maxNestingDepthMustBePositive(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Maximum nesting depth must be at least 1.');
        Element::setMaxNestingDepth(0);
    }

    /**
     * A rejected decoding must not leave the depth counter in a broken state.
     */
    #[Test]
    public function depthCounterIsRestoredAfterFailure(): void
    {
        for ($i = 0; $i < 3; ++$i) {
            try {
                Element::fromDER(self::indefiniteLengthSequences(Element::DEFAULT_MAX_NESTING_DEPTH + 1));
                static::fail('Deeply nested structure should have been rejected.');
            } catch (DecodeException) {
                // expected
            }
        }
        $el = Element::fromDER(self::definiteLengthSequences(Element::DEFAULT_MAX_NESTING_DEPTH));
        static::assertTrue($el->isType(Element::TYPE_SEQUENCE));
    }

    /**
     * Nested indefinite length SEQUENCEs, two bytes per nesting level.
     */
    private static function indefiniteLengthSequences(int $depth): string
    {
        return str_repeat("\x30\x80", $depth) . str_repeat("\x00\x00", $depth);
    }

    /**
     * Nested definite length SEQUENCEs.
     */
    private static function definiteLengthSequences(int $depth): string
    {
        $der = '';
        for ($i = 0; $i < $depth; ++$i) {
            $der = "\x30" . self::encodeLength(mb_strlen($der, '8bit')) . $der;
        }
        return $der;
    }

    private static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }
        return chr(0x80 | mb_strlen($bytes, '8bit')) . $bytes;
    }
}
