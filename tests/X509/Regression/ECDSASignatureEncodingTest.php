<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use function chr;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Signature\ECSignature;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use function strlen;

/**
 * A certificate's signature value is not covered by the signature it carries, so anything the decoder accepted and
 * then normalised away produced another byte string that verified just as well. ECSignature re-encoded r and s
 * canonically and handed that re-encoding to the crypto engine, so trailing bytes, a BER length and a non-minimal
 * INTEGER never reached OpenSSL. One certificate therefore had an unlimited supply of accepted encodings, each with
 * its own digest, which defeats pinning, deny-listing and deduplicating by the digest of what was received.
 *
 * OpenSSL rejects every one of these encodings.
 *
 * @internal
 */
final class ECDSASignatureEncodingTest extends TestCase
{
    /**
     * @return iterable<string, array{callable(string): string}>
     */
    public static function mutations(): iterable
    {
        yield 'trailing bytes' => [
            static fn (string $der): string => $der . "\xde\xad\xbe\xef",
        ];
        yield 'long form length' => [
            static fn (string $der): string => "\x30\x81" . chr(strlen($der) - 2) . substr($der, 2),
        ];
        yield 'a third element' => [static function (string $der): string {
            $seq = Element::fromDER($der)->asUnspecified()
                ->asSequence();

            return Sequence::create(
                $seq->at(0)
                    ->asElement(),
                $seq->at(1)
                    ->asElement(),
                Integer::create(1)
            )->toDER();
        }];
    }

    #[Test]
    #[DataProvider('mutations')]
    public function anEncodingThatIsNotCanonicalDERIsRejected(callable $mutate): void
    {
        $der = self::signatureValue();
        $this->expectException(DecodeException::class);
        ECSignature::fromDER($mutate($der));
    }

    #[Test]
    public function theCanonicalEncodingIsStillAccepted(): void
    {
        $der = self::signatureValue();
        $signature = ECSignature::fromDER($der);
        static::assertSame($der, $signature->toDER());
    }

    #[Test]
    public function aCertificateWithAMutatedSignatureValueNoLongerVerifies(): void
    {
        $leaf = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        $seq = Element::fromDER($leaf->toDER())->asUnspecified()
            ->asSequence();
        $mutated = Sequence::create(
            $seq->at(0)
                ->asElement(),
            $seq->at(1)
                ->asElement(),
            BitString::create($seq->at(2)->asBitString()->string() . "\xde\xad\xbe\xef")
        )->toDER();

        $this->expectException(DecodeException::class);
        Certificate::fromDER($mutated);
    }

    #[Test]
    public function everyFreshlyProducedSignatureRoundTrips(): void
    {
        for ($i = 1; $i <= 32; ++$i) {
            $signature = ECSignature::create((string) $i, (string) ($i * 7919));
            $der = $signature->toDER();
            static::assertSame($der, ECSignature::fromDER($der)->toDER());
        }
    }

    private static function signatureValue(): string
    {
        $leaf = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));

        return Element::fromDER($leaf->toDER())->asUnspecified()
            ->asSequence()
            ->at(2)
            ->asBitString()
            ->string();
    }
}
