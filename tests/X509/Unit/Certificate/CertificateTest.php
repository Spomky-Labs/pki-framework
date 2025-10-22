<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Signature\Signature;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use UnexpectedValueException;
use function strval;

/**
 * @internal
 */
final class CertificateTest extends TestCase
{
    private static ?OneAsymmetricKey $_privateKeyInfo = null;

    public static function setUpBeforeClass(): void
    {
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_privateKeyInfo = null;
    }

    #[Test]
    public function create(): Certificate
    {
        $pki = self::$_privateKeyInfo->publicKeyInfo();
        $tc = TBSCertificate::create(
            Name::fromString('cn=Subject'),
            $pki,
            Name::fromString('cn=Issuer'),
            Validity::fromStrings(null, null)
        );
        $tc = $tc->withVersion(TBSCertificate::VERSION_1)
            ->withSerialNumber(0)
            ->withSignature(SHA1WithRSAEncryptionAlgorithmIdentifier::create());
        $signature = Crypto::getDefault()->sign($tc->toASN1()->toDER(), self::$_privateKeyInfo, $tc->signature());
        $cert = Certificate::create($tc, $tc->signature(), $signature);
        static::assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    #[Test]
    #[Depends('create')]
    public function encode(Certificate $cert): string
    {
        $seq = $cert->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): Certificate
    {
        $cert = Certificate::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Certificate $ref, Certificate $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function tBSCertificate(Certificate $cert)
    {
        static::assertInstanceOf(TBSCertificate::class, $cert->tbsCertificate());
    }

    #[Test]
    #[Depends('create')]
    public function signatureAlgorithm(Certificate $cert)
    {
        static::assertInstanceOf(AlgorithmIdentifier::class, $cert->signatureAlgorithm());
    }

    #[Test]
    #[Depends('create')]
    public function signature(Certificate $cert)
    {
        static::assertInstanceOf(Signature::class, $cert->signatureValue());
    }

    #[Test]
    #[Depends('create')]
    public function toPEM(Certificate $cert)
    {
        $pem = $cert->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    #[Test]
    #[Depends('toPEM')]
    public function pEMType(PEM $pem)
    {
        static::assertSame(PEM::TYPE_CERTIFICATE, $pem->type());
    }

    #[Test]
    #[Depends('toPEM')]
    public function fromPEM(PEM $pem)
    {
        $cert = Certificate::fromPEM($pem);
        static::assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('fromPEM')]
    public function pEMRecoded(Certificate $ref, Certificate $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    public function fromInvalidPEMFail()
    {
        $this->expectException(UnexpectedValueException::class);
        Certificate::fromPEM(PEM::create('nope', ''));
    }

    #[Test]
    #[Depends('create')]
    public function toStringMethod(Certificate $cert)
    {
        static::assertIsString(strval($cert));
    }

    #[Test]
    #[Depends('create')]
    public function invalidAlgoFail(Certificate $cert)
    {
        $seq = $cert->toASN1();
        $algo = GenericAlgorithmIdentifier::create('1.3.6.1.3');
        $seq = $seq->withReplaced(1, $algo->toASN1());
        $this->expectException(UnexpectedValueException::class);
        Certificate::fromASN1($seq);
    }
}
