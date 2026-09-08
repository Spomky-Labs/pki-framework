<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Regression;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Real;
use SpomkyLabs\Pki\ASN1\Type\Primitive\RelativeOID;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * A long form tag number and an OID sub-identifier were both folded into a BigInteger seven bits at a time, with no
 * bound on how many continuation octets an attacker could write. The accumulator is rebuilt on every step, so the
 * cost was quadratic in the length of the run: eight kilobytes of them took seconds, thirty-two kilobytes took
 * minutes, and all of it was spent inside Certificate::fromDER() before any signature was checked. Real's decimal
 * normalisation divided by ten once per digit, with the same shape.
 *
 * A field beyond nine octets cannot name a type or an arc this library implements, so it is refused.
 *
 * @internal
 */
final class UnboundedBase128FieldTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function overlongFields(): iterable
    {
        // 0x1f introduces a long form tag; every 0x80-set octet asks for another seven bits.
        yield 'long form tag' => [
            "\x1f" . str_repeat("\xff", 64) . "\x01\x00",
            'Long form identifier is too long.',
        ];
        // An OBJECT IDENTIFIER whose single sub-identifier spans 64 octets.
        yield 'object identifier sub-identifier' => [
            "\x06\x41\x2a" . str_repeat("\xff", 63) . "\x01",
            'Sub-identifier is too long.',
        ];
        // The same for a RELATIVE-OID, universal tag 13.
        yield 'relative oid sub-identifier' => [
            "\x0d\x40" . str_repeat("\xff", 63) . "\x01",
            'Sub-identifier is too long.',
        ];
    }

    #[Test]
    #[DataProvider('overlongFields')]
    public function anOverlongBase128FieldIsRefused(string $der, string $message): void
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage($message);
        Element::fromDER($der);
    }

    #[Test]
    public function anOverlongTagIsRefusedThroughACertificateEntryPoint(): void
    {
        // The shape that used to let brick/math's IntegerOverflowException escape the decoding contract as well.
        $der = "\x30\x0d\x1f" . str_repeat("\x81", 10) . "\x00\x00";

        $this->expectException(DecodeException::class);
        Certificate::fromDER($der);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ordinaryObjectIdentifiers(): iterable
    {
        yield 'basicConstraints' => ['2.5.29.19'];
        yield 'sha256WithRSAEncryption' => ['1.2.840.113549.1.1.11'];
        yield 'a large but representable arc' => ['1.2.9223372036854775807'];
    }

    #[Test]
    #[DataProvider('ordinaryObjectIdentifiers')]
    public function ordinaryObjectIdentifiersStillDecode(string $oid): void
    {
        $der = ObjectIdentifier::create($oid)->toDER();
        static::assertSame($oid, ObjectIdentifier::fromDER($der)->oid());
    }

    #[Test]
    public function ordinaryRelativeOIDsStillDecode(): void
    {
        $der = RelativeOID::create('8571.3.2')->toDER();
        static::assertSame('8571.3.2', RelativeOID::fromDER($der)->oid());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function realValues(): iterable
    {
        yield 'an integral value' => ['1000000'];
        yield 'a value with no trailing zeroes' => ['123'];
        yield 'a negative value' => ['-4500'];
        yield 'zero' => ['0'];
    }

    #[Test]
    #[DataProvider('realValues')]
    public function realNormalisationKeepsTheValue(string $number): void
    {
        $real = Real::fromString($number);
        static::assertSame((float) $number, Real::fromDER($real->toDER())->floatVal());
    }
}
