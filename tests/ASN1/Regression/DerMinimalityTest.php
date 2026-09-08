<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Regression;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * A parsed certificate must re-encode to the bytes it arrived as.
 *
 * The decoder used to accept a range of non-minimal encodings, so many distinct byte strings decoded to one
 * object. The outer certificate SEQUENCE header, the signatureAlgorithm and the signatureValue are not covered by
 * the signature, so one legitimately issued certificate yielded an unbounded family of byte-distinct encodings
 * that all parsed to it. A caller that hashes what arrived — which is what browsers, OpenSSL and Certificate
 * Transparency logs do — would see a different certificate each time.
 *
 * @internal
 */
final class DerMinimalityTest extends TestCase
{
    /**
     * @return Iterator<string, array{string}>
     */
    public static function nonMinimalEncodingProvider(): Iterator
    {
        // X.690 sect. 10.1: the length uses the minimum number of octets
        yield 'long form length with a leading zero octet' => ["\x02\x82\x00\x01\x01"];
        yield 'long form length for a value the short form fits' => ["\x02\x81\x01\x01"];
        yield 'long form length, four octets, value 1' => ["\x02\x84\x00\x00\x00\x01\x01"];

        // X.690 sect. 8.1.2.3 and 8.1.2.4.2 c: the tag number uses the short form below 31, and no leading zeroes
        yield 'long form tag number below 31' => ["\x1f\x02\x01\x01"];
        yield 'long form tag number with a leading 0x80 octet' => ["\x3f\x80\x22\x00"];

        // X.690 sect. 8.3.2: an integer uses the minimum number of octets
        yield 'integer padded with a leading 0x00' => ["\x02\x02\x00\x01"];
        yield 'negative integer padded with a leading 0xff' => ["\x02\x02\xff\x80"];
        yield 'enumerated padded with a leading 0x00' => ["\x0a\x02\x00\x01"];

        // X.690 sect. 8.19: an object identifier has at least one sub-identifier, each minimally encoded
        yield 'object identifier with a padded sub-identifier' => ["\x06\x04\x55\x1d\x80\x13"];
        yield 'empty object identifier' => ["\x06\x00"];
        yield 'empty relative object identifier' => ["\x0d\x00"];

        // X.690 sect. 8: a type whose contents are a single value is primitive
        yield 'constructed integer' => ["\x22\x01\x01"];
        yield 'constructed boolean' => ["\x21\x01\xff"];
        yield 'constructed object identifier' => ["\x26\x03\x55\x1d\x13"];
        yield 'constructed enumerated' => ["\x2a\x01\x01"];

        // there is no last octet to hold the unused bits, and numBits() came back negative
        yield 'empty bit string with unused bits' => ["\x03\x01\x07"];
    }

    #[Test]
    #[DataProvider('nonMinimalEncodingProvider')]
    public function aNonMinimalEncodingIsRejected(string $der): void
    {
        $this->expectException(DecodeException::class);
        Element::fromDER($der);
    }

    /**
     * @return Iterator<string, array{string}>
     */
    public static function minimalEncodingProvider(): Iterator
    {
        yield 'integer 1' => ["\x02\x01\x01"];
        yield 'integer -128' => ["\x02\x01\x80"];
        yield 'integer 0' => ["\x02\x01\x00"];
        yield 'integer 128, which needs the leading zero' => ["\x02\x02\x00\x80"];
        yield 'integer -129, which needs the leading 0xff' => ["\x02\x02\xff\x7f"];
        yield 'basicConstraints object identifier' => ["\x06\x03\x55\x1d\x13"];
        yield 'empty bit string' => ["\x03\x01\x00"];
        yield 'bit string with unused bits' => ["\x03\x02\x07\x80"];
        yield 'long form length that the short form cannot hold' => ["\x04\x81\x80" . str_repeat("\x00", 128)];
    }

    #[Test]
    #[DataProvider('minimalEncodingProvider')]
    public function aMinimalEncodingStillDecodes(string $der): void
    {
        static::assertSame($der, Element::fromDER($der)->toDER());
    }

    #[Test]
    public function aShippedCertificateRoundTripsToTheBytesItArrivedAs(): void
    {
        $der = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem')->data();

        static::assertSame($der, Certificate::fromDER($der)->toDER());
    }
}
