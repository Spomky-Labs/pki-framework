<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoEncoding;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const PREG_NO_ERROR;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoEncoding\PEMBundle;
use UnexpectedValueException;

/**
 * PEM_REGEX used two lazy `.+?` groups under the `s` modifier with no anchoring, so for every "-----BEGIN " start
 * position the engine tried every "-----" for the label and, for each one, expanded the payload across the whole
 * remainder. Repeated BEGIN lines with no matching END drove cubic backtracking: 3.8 KB cost about 0.26 s against
 * 0.000022 s for a real certificate, and PCRE's backtrack limit turned the abort into "not a PEM formatted string",
 * which is indistinguishable from malformed input and disappears as soon as a host raises the limit.
 *
 * @internal
 */
final class PEMPatternTest extends TestCase
{
    /**
     * @return iterable<string, array{int}>
     */
    public static function hostileSizes(): iterable
    {
        yield '200 begin lines' => [200];
        yield '800 begin lines' => [800];
        yield '3200 begin lines' => [3200];
    }

    #[Test]
    #[DataProvider('hostileSizes')]
    public function repeatedBeginLinesDoNotBacktrack(int $count): void
    {
        $input = str_repeat("\n-----BEGIN A-----\n", $count);

        $started = microtime(true);
        try {
            PEM::fromString($input);
            static::fail('Expected the input to be refused.');
        } catch (UnexpectedValueException) {
            // the input carries no complete block, which is the right answer
        }
        $elapsed = microtime(true) - $started;

        // the old pattern took roughly a quarter of a second at the smallest of these sizes and grew cubically
        static::assertLessThan(1.0, $elapsed);
        static::assertSame(PREG_NO_ERROR, preg_last_error());
    }

    #[Test]
    public function aRealCertificateStillParses(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem');
        static::assertSame(PEM::TYPE_CERTIFICATE, $pem->type());
        static::assertNotSame('', $pem->data());
    }

    #[Test]
    public function aBundleStillParses(): void
    {
        $bundle = PEMBundle::fromFile(TEST_ASSETS_DIR . '/certs/intermediate-bundle.pem');
        static::assertCount(2, $bundle);
    }

    #[Test]
    public function aRoundTripIsUnchanged(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem');
        static::assertSame($pem->data(), PEM::fromString($pem->string())->data());
    }

    #[Test]
    public function unpaddedBase64IsRefused(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem');
        $unpadded = str_replace('=', '', $pem->string());

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Failed to decode PEM data.');
        PEM::fromString($unpadded);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function labelsThatAreNotLabels(): iterable
    {
        yield 'a label spanning a line break' => ["-----BEGIN CERT\nIFICATE-----\nQUJD\n-----END CERT\nIFICATE-----"];
        yield 'a label with a dash run' => ["-----BEGIN A-----B-----\nQUJD\n-----END A-----B-----"];
    }

    #[Test]
    #[DataProvider('labelsThatAreNotLabels')]
    public function aLabelIsASingleLineOfPlainCharacters(string $input): void
    {
        $this->expectException(UnexpectedValueException::class);
        PEM::fromString($input);
    }
}
