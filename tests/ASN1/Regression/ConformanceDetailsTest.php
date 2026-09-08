<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Regression;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\PrintableString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use function sprintf;
use UnexpectedValueException;

/**
 * Small conformance gaps that were each inert on their own.
 *
 * @internal
 */
final class ConformanceDetailsTest extends TestCase
{
    #[Test]
    public function numberValidationIsAnchored(): void
    {
        // preg_match('/-?\d+/') matches anywhere in the subject, so the check was decorative and its error
        // message misleading. Nothing escaped, because BigInt::create() caught the resulting failure.
        foreach (['abc1def', '1; DROP', "1\nx"] as $subject) {
            try {
                Integer::create($subject);
                static::fail(sprintf('Expected "%s" to be refused.', $subject));
            } catch (InvalidArgumentException $e) {
                static::assertStringContainsString('is not a valid number', $e->getMessage());
            }
        }

        static::assertSame('12', Integer::create('12')->number());
        static::assertSame('-12', Integer::create('-12')->number());
    }

    #[Test]
    public function printableStringRefusesTheClosingBracket(): void
    {
        // X.680 sect. 41, table 10 has no ']' in the PrintableString character set, and other implementations
        // reject "\x13\x01\x5d".
        $this->expectException(InvalidArgumentException::class);
        PrintableString::create(']');
    }

    #[Test]
    public function printableStringStillAcceptsItsOwnCharacterSet(): void
    {
        $string = "Example Ltd. (test) 'x' +1,2-3/4:5=6?";

        static::assertSame($string, PrintableString::create($string)->string());
    }

    #[Test]
    public function pemRefusesUnpaddedBase64(): void
    {
        // base64_decode(..., true) is strict about the alphabet but not about padding, so a blob OpenSSL refuses
        // was accepted here.
        $payload = rtrim(base64_encode(str_repeat('A', 10)), '=');

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Failed to decode PEM data.');
        PEM::fromString("-----BEGIN CERTIFICATE-----\n{$payload}\n-----END CERTIFICATE-----");
    }

    #[Test]
    public function pemStillAcceptsPaddedBase64(): void
    {
        $payload = base64_encode(str_repeat('A', 10));
        $pem = PEM::fromString("-----BEGIN CERTIFICATE-----\n{$payload}\n-----END CERTIFICATE-----");

        static::assertSame(PEM::TYPE_CERTIFICATE, $pem->type());
        static::assertSame(str_repeat('A', 10), $pem->data());
    }

    #[Test]
    public function pemLabelIsAnchoredToASingleLine(): void
    {
        // The label group was (.+?) under /s, so type() could come back as "CERTIFICATE " or hold a newline.
        // Every in-library consumer compares with !== and rejects, so this was inert.
        $payload = base64_encode(str_repeat('A', 10));

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Not a PEM formatted string.');
        PEM::fromString("-----BEGIN CERTIFICATE \n{$payload}\n-----END CERTIFICATE \n-----");
    }

    #[Test]
    public function theOffsetIsWrittenBackWhenTheCallersVariableIsNull(): void
    {
        // fromDER() used isset() rather than func_num_args(), which contradicted the docblock: a caller looping
        // on the offset would spin. SignedDER worked around it with $offset ?? 0.
        $der = "\x02\x01\x01\x02\x01\x02";
        $offset = null;

        Element::fromDER($der, $offset);
        static::assertSame(3, $offset);

        Element::fromDER($der, $offset);
        static::assertSame(6, $offset);
    }
}
