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
 * RFC 1421 headers, which the traditional OpenSSL encrypted key format carries (`Proc-Type`, `DEK-Info`).
 *
 * @internal
 */
final class PEMHeadersTest extends TestCase
{
    private const LEGACY = "-----BEGIN RSA PRIVATE KEY-----\n" .
        "Proc-Type: 4,ENCRYPTED\n" .
        "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n" .
        "\n" .
        "QUJDREVG\n" .
        '-----END RSA PRIVATE KEY-----';

    #[Test]
    public function headersAreParsed(): void
    {
        $pem = PEM::fromString(self::LEGACY);
        static::assertSame(PEM::TYPE_RSA_PRIVATE_KEY, $pem->type());
        static::assertSame('ABCDEF', $pem->data());
        static::assertSame('ABCDEF', PEM::fromString(str_replace('QUJDREVG', "QUJD\nREVG", self::LEGACY))->data());
        static::assertSame([
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => 'AES-128-CBC,00112233445566778899AABBCCDDEEFF',
        ], $pem->headers());
        static::assertTrue($pem->hasHeaders());
        static::assertTrue($pem->isEncrypted());
        static::assertSame('4,ENCRYPTED', $pem->header(PEM::HEADER_PROC_TYPE));
        static::assertNull($pem->header('proc-type'));
    }

    #[Test]
    public function headersRoundTrip(): void
    {
        $pem = PEM::fromString(self::LEGACY);
        static::assertSame(self::LEGACY, $pem->string());
        static::assertEquals($pem, PEM::fromString($pem->string()));
    }

    #[Test]
    public function aFixtureRoundTrips(): void
    {
        $str = trim((string) file_get_contents(TEST_ASSETS_DIR . '/encrypted/legacy_ec_des3.pem'));
        $pem = PEM::fromString($str);
        static::assertTrue($pem->isEncrypted());
        static::assertSame($str, $pem->string());
    }

    #[Test]
    public function crlfLineBreaksAndSurroundingBlanksAreAccepted(): void
    {
        $pem = PEM::fromString(
            "-----BEGIN X-----\r\nName:\tvalue with  spaces \t\r\nOther:\r\n\r\nQUJD\r\n-----END X-----\r\n"
        );
        static::assertSame([
            'Name' => 'value with  spaces',
            'Other' => '',
        ], $pem->headers());
        static::assertSame('ABC', $pem->data());
        static::assertFalse($pem->isEncrypted());
    }

    #[Test]
    public function aBlockWithoutHeadersIsUnchanged(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        static::assertSame([], $pem->headers());
        static::assertFalse($pem->hasHeaders());
        static::assertFalse($pem->isEncrypted());
        static::assertStringNotContainsString("\n\n", $pem->string());
    }

    #[Test]
    public function aBundleKeepsHeadersPerBlock(): void
    {
        $plain = (string) file_get_contents(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $bundle = PEMBundle::fromString($plain . "\n" . self::LEGACY . "\n" . $plain);
        static::assertCount(3, $bundle);
        [$first, $second, $third] = $bundle->all();
        static::assertFalse($first->hasHeaders());
        static::assertTrue($second->isEncrypted());
        static::assertSame('ABCDEF', $second->data());
        static::assertFalse($third->hasHeaders());
        static::assertEquals($bundle, PEMBundle::fromString($bundle->string()));
    }

    #[Test]
    public function createWritesHeaders(): void
    {
        $pem = PEM::create('X', 'ABC', [
            'A' => '1',
            'B-2' => '',
        ]);
        static::assertSame("-----BEGIN X-----\nA: 1\nB-2: \n\nQUJD\n-----END X-----", $pem->string());
        static::assertSame("-----BEGIN X-----\nQUJD\n-----END X-----", PEM::create('X', 'ABC')->string());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function procTypes(): iterable
    {
        yield 'spaces around the comma' => ['4 , ENCRYPTED'];
        yield 'canonical' => ['4,ENCRYPTED'];
    }

    #[Test]
    #[DataProvider('procTypes')]
    public function isEncrypted(string $procType): void
    {
        static::assertTrue(PEM::create('X', '', [
            'Proc-Type' => $procType,
        ])->isEncrypted());
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function notEncrypted(): iterable
    {
        yield 'MIC-ONLY' => [[
            'Proc-Type' => '4,MIC-ONLY',
        ]];
        yield 'prefix' => [[
            'Proc-Type' => '14,ENCRYPTED',
        ]];
        yield 'suffix' => [[
            'Proc-Type' => '4,ENCRYPTED2',
        ]];
        yield 'other header' => [[
            'DEK-Info' => 'AES-128-CBC,00',
        ]];
    }

    /**
     * @param array<string, string> $headers
     */
    #[Test]
    #[DataProvider('notEncrypted')]
    public function isNotEncrypted(array $headers): void
    {
        static::assertFalse(PEM::create('X', '', $headers)->isEncrypted());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedHeaders(): iterable
    {
        yield 'no blank line after the headers' => ["-----BEGIN X-----\nA: 1\nQUJD\n-----END X-----"];
        yield 'a name with an underscore' => ["-----BEGIN X-----\nA_B: 1\n\nQUJD\n-----END X-----"];
        yield 'a name starting with a dash' => ["-----BEGIN X-----\n-A: 1\n\nQUJD\n-----END X-----"];
        yield 'a folded continuation line' => ["-----BEGIN X-----\nA: 1\n 2\n\nQUJD\n-----END X-----"];
        yield 'a control character in a value' => ["-----BEGIN X-----\nA: 1\x00\n\nQUJD\n-----END X-----"];
        yield 'a non ASCII value' => ["-----BEGIN X-----\nA: \xC3\xA9\n\nQUJD\n-----END X-----"];
        yield 'a header after the payload' => ["-----BEGIN X-----\nQUJD\nA: 1\n\n-----END X-----"];
        yield 'headers and no payload' => ["-----BEGIN X-----\nA: 1\n\n-----END X-----"];
    }

    #[Test]
    #[DataProvider('malformedHeaders')]
    public function malformedHeadersAreRefused(string $input): void
    {
        $this->expectException(UnexpectedValueException::class);
        PEM::fromString($input);
    }

    #[Test]
    #[DataProvider('malformedHeaders')]
    public function malformedHeadersAreRefusedInABundle(string $input): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('No PEM blocks.');
        PEMBundle::fromString($input);
    }

    #[Test]
    public function duplicateHeadersAreRefused(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Duplicate PEM header A.');
        PEM::fromString("-----BEGIN X-----\nA: 1\nA: 2\n\nQUJD\n-----END X-----");
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function invalidHeaders(): iterable
    {
        yield 'a line break in a value' => [[
            'A' => "1\nB: 2",
        ], 'Invalid PEM header value.'];
        yield 'a carriage return in a value' => [[
            'A' => "1\r",
        ], 'Invalid PEM header value.'];
        yield 'a colon in a name' => [[
            'A:B' => '1',
        ], 'Invalid PEM header name.'];
        yield 'an empty name' => [[
            '' => '1',
        ], 'Invalid PEM header name.'];
        yield 'a line break after a name' => [[
            "A\n" => '1',
        ], 'Invalid PEM header name.'];
        yield 'a space before a name' => [[
            ' A' => '1',
        ], 'Invalid PEM header name.'];
    }

    /**
     * @param array<string, string> $headers
     */
    #[Test]
    #[DataProvider('invalidHeaders')]
    public function createRefusesHeadersThatWouldNotRoundTrip(array $headers, string $message): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage($message);
        PEM::create('X', '', $headers);
    }

    #[Test]
    public function aTabInAValueIsAccepted(): void
    {
        static::assertSame([
            'A' => "1\t2",
        ], PEM::create('X', '', [
            'A' => "1\t2",
        ])->headers());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function hostileInputs(): iterable
    {
        yield 'header lines with no blank line' => ["-----BEGIN A-----\n" . str_repeat("A: b\n", 20000)];
        yield 'repeated begin and header lines' => [str_repeat("-----BEGIN A-----\nA: b\n", 5000)];
        yield 'headers ended by a blank line and no end' => [str_repeat("-----BEGIN A-----\nA: b\n\nQUJD\n", 5000)];
        yield 'a long header value' => ["-----BEGIN A-----\nA: " . str_repeat('b', 200000) . "\n\nQUJD\n"];
    }

    #[Test]
    #[DataProvider('hostileInputs')]
    public function hostileHeadersDoNotBacktrack(string $input): void
    {
        $started = microtime(true);
        try {
            PEMBundle::fromString($input);
            static::fail('Expected the input to be refused.');
        } catch (UnexpectedValueException) {
            // the input carries no complete block
        }
        static::assertLessThan(1.0, microtime(true) - $started);
        static::assertSame(PREG_NO_ERROR, preg_last_error());
    }
}
