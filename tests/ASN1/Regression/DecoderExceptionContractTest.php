<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Regression;

use Brick\Math\BigInteger;
use function chr;
use Exception;
use Iterator;
use OutOfBoundsException;
use const PHP_INT_MAX;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use function sprintf;
use Throwable;
use UnexpectedValueException;

/**
 * fromDER() must only ever throw DecodeException on malformed input.
 *
 * A TypeError in particular derives from Error, not Exception, so it escapes the catch (Exception) that callers
 * commonly wrap decoding in, and takes the process down instead of producing an error response.
 *
 * @internal
 */
final class DecoderExceptionContractTest extends TestCase
{
    /**
     * @return Iterator<string, array{string}>
     */
    public static function malformedInputProvider(): Iterator
    {
        yield 'long form length beyond PHP_INT_MAX' => ["\x30\x88\xff\xff\xff\xff\xff\xff\xff\xff"];
        yield 'long form length beyond data' => ["\x30\x84\x7f\xff\xff\xff"];
        yield 'constructed octet string holding an integer' => ["\x24\x03\x02\x01\x05"];
        yield 'constructed octet string, indefinite length' => ["\x24\x80\x02\x01\x05\x00\x00"];
        yield 'constructed octet string holding another string type' => ["\x24\x03\x0c\x01\x41"];
        yield 'zero length integer' => ["\x02\x00"];
        yield 'zero length integer nested' => ["\x30\x02\x02\x00"];
        yield 'zero length enumerated' => ["\x0a\x00"];
        yield 'indefinite length octet string' => ["\x04\x80\x00\x00"];
        yield 'indefinite length integer' => ["\x02\x80\x00\x00"];
        yield 'indefinite length object identifier' => ["\x06\x80\x00\x00"];
        yield 'indefinite length bit string' => ["\x03\x80\x00\x00"];
        yield 'indefinite length utc time' => ["\x17\x80\x00\x00"];
    }

    #[Test]
    #[DataProvider('malformedInputProvider')]
    public function malformedInputThrowsDecodeException(string $der): void
    {
        $this->expectException(DecodeException::class);
        Element::fromDER($der);
    }

    #[Test]
    #[DataProvider('malformedInputProvider')]
    public function malformedInputIsCatchableAsException(string $der): void
    {
        try {
            Element::fromDER($der);
            static::fail('Expected the decoder to reject this input.');
        } catch (Exception $e) {
            static::assertInstanceOf(DecodeException::class, $e);
        } catch (Throwable $e) {
            static::fail(sprintf('%s escaped catch (Exception): %s', $e::class, $e->getMessage()));
        }
    }

    #[Test]
    public function certificateEntryPointOnlyThrowsCatchableExceptions(): void
    {
        // A mutation corpus derived from a valid certificate must never take the process down or raise
        // an Error rather than an Exception.
        $escaped = [];
        foreach (self::mutations() as $mutated) {
            try {
                Certificate::fromDER($mutated);
            } catch (Exception) {
                // expected: every decoding failure is an Exception
            } catch (Throwable $e) {
                $escaped[$e::class] = ($escaped[$e::class] ?? 0) + 1;
            }
        }

        static::assertSame([], $escaped, 'Errors escaped catch (Exception): ' . json_encode($escaped));
    }

    #[Test]
    public function certificateEntryPointStaysWithinItsExceptionContract(): void
    {
        // Beyond being catchable, a decoding failure must be one of the types callers are told to expect.
        // OutOfBoundsException is tolerated: Structure::at() raises it when an X.501 structure is too short,
        // which is a shape check in the X.501 layer rather than an ASN.1 decoding failure.
        $allowed = [DecodeException::class, UnexpectedValueException::class, OutOfBoundsException::class];

        $offContract = [];
        foreach (self::mutations() as $mutated) {
            try {
                Certificate::fromDER($mutated);
            } catch (Throwable $e) {
                foreach ($allowed as $class) {
                    if ($e instanceof $class) {
                        continue 2;
                    }
                }
                $offContract[$e::class] = ($offContract[$e::class] ?? 0) + 1;
            }
        }

        static::assertSame([], $offContract, 'Off-contract exceptions: ' . json_encode($offContract));
    }

    #[Test]
    public function certificateVersionBeyondIntRangeIsReported(): void
    {
        // The version is read as an int; a version that does not fit used to let brick/math's
        // IntegerOverflowException out of Certificate::fromDER().
        $tbs = Sequence::create(
            ExplicitlyTaggedType::create(0, Integer::create(BigInteger::of(PHP_INT_MAX)->plus(1))),
            Integer::create(1)
        );

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Unsupported certificate version');
        TBSCertificate::fromASN1($tbs);
    }

    /**
     * A deterministic mutation corpus derived from a valid certificate.
     *
     * @return iterable<string>
     */
    private static function mutations(): iterable
    {
        $der = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'))->toDER();

        mt_srand(1337);
        for ($i = 0; $i < 2000; ++$i) {
            $mutated = $der;
            for ($m = 0, $n = mt_rand(1, 4); $m < $n; ++$m) {
                $pos = mt_rand(0, mb_strlen($mutated, '8bit') - 1);
                $mutated[$pos] = chr(mt_rand(0, 255));
            }
            yield $mutated;
        }
    }
}
