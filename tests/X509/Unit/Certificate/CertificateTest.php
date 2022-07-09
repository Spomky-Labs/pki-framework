<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Signature\Signature;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\Validity;
use function strval;
use UnexpectedValueException;

/**
 * @internal
 */
final class CertificateTest extends TestCase
{
    private static $_privateKeyInfo;

    public static function setUpBeforeClass(): void
    {
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_privateKeyInfo = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $pki = self::$_privateKeyInfo->publicKeyInfo();
        $tc = new TBSCertificate(
            Name::fromString('cn=Subject'),
            $pki,
            Name::fromString('cn=Issuer'),
            Validity::fromStrings(null, null)
        );
        $tc = $tc->withVersion(TBSCertificate::VERSION_1)
            ->withSerialNumber(0)
            ->withSignature(new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $signature = Crypto::getDefault()->sign($tc->toASN1() ->toDER(), self::$_privateKeyInfo, $tc->signature());
        $cert = new Certificate($tc, $tc->signature(), $signature);
        $this->assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Certificate $cert)
    {
        $seq = $cert->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $cert = Certificate::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Certificate $ref, Certificate $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tBSCertificate(Certificate $cert)
    {
        $this->assertInstanceOf(TBSCertificate::class, $cert->tbsCertificate());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function signatureAlgorithm(Certificate $cert)
    {
        $this->assertInstanceOf(AlgorithmIdentifier::class, $cert->signatureAlgorithm());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function signature(Certificate $cert)
    {
        $this->assertInstanceOf(Signature::class, $cert->signatureValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toPEM(Certificate $cert)
    {
        $pem = $cert->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends toPEM
     *
     * @test
     */
    public function pEMType(PEM $pem)
    {
        $this->assertEquals(PEM::TYPE_CERTIFICATE, $pem->type());
    }

    /**
     * @depends toPEM
     *
     * @test
     */
    public function fromPEM(PEM $pem)
    {
        $cert = Certificate::fromPEM($pem);
        $this->assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends create
     * @depends fromPEM
     *
     * @test
     */
    public function pEMRecoded(Certificate $ref, Certificate $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @test
     */
    public function fromInvalidPEMFail()
    {
        $this->expectException(UnexpectedValueException::class);
        Certificate::fromPEM(new PEM('nope', ''));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(Certificate $cert)
    {
        $this->assertIsString(strval($cert));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function invalidAlgoFail(Certificate $cert)
    {
        $seq = $cert->toASN1();
        $algo = new GenericAlgorithmIdentifier('1.3.6.1.3');
        $seq = $seq->withReplaced(1, $algo->toASN1());
        $this->expectException(UnexpectedValueException::class);
        Certificate::fromASN1($seq);
    }
}
