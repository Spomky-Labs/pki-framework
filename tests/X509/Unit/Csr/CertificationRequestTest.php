<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Csr;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Signature\Signature;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequest;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequestInfo;
use function strval;
use UnexpectedValueException;

/**
 * @internal
 */
final class CertificationRequestTest extends TestCase
{
    private static ?Name $_subject = null;

    private static ?OneAsymmetricKey $_privateKeyInfo = null;

    public static function setUpBeforeClass(): void
    {
        self::$_subject = Name::fromString('cn=Subject');
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_subject = null;
        self::$_privateKeyInfo = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $pkinfo = self::$_privateKeyInfo->publicKeyInfo();
        $cri = CertificationRequestInfo::create(self::$_subject, $pkinfo);
        $data = $cri->toASN1()
            ->toDER();
        $algo = SHA256WithRSAEncryptionAlgorithmIdentifier::create();
        $signature = Crypto::getDefault()->sign($data, self::$_privateKeyInfo, $algo);
        $cr = CertificationRequest::create($cri, $algo, $signature);
        static::assertInstanceOf(CertificationRequest::class, $cr);
        return $cr;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(CertificationRequest $cr)
    {
        $seq = $cr->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
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
        $cr = CertificationRequest::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(CertificationRequest::class, $cr);
        return $cr;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(CertificationRequest $ref, CertificationRequest $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function certificationRequestInfo(CertificationRequest $cr)
    {
        static::assertInstanceOf(CertificationRequestInfo::class, $cr->certificationRequestInfo());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function algo(CertificationRequest $cr)
    {
        static::assertInstanceOf(SHA256WithRSAEncryptionAlgorithmIdentifier::class, $cr->signatureAlgorithm());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function signature(CertificationRequest $cr)
    {
        static::assertInstanceOf(Signature::class, $cr->signature());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function verify(CertificationRequest $cr)
    {
        static::assertTrue($cr->verify());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function invalidAlgoFail(CertificationRequest $cr)
    {
        $seq = $cr->toASN1();
        $algo = GenericAlgorithmIdentifier::create('1.3.6.1.3');
        $seq = $seq->withReplaced(1, $algo->toASN1());
        $this->expectException(UnexpectedValueException::class);
        CertificationRequest::fromASN1($seq);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toPEM(CertificationRequest $cr)
    {
        $pem = $cr->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(CertificationRequest $cr)
    {
        static::assertIsString(strval($cr));
    }

    /**
     * @depends toPEM
     *
     * @test
     */
    public function pEMType(PEM $pem)
    {
        static::assertEquals(PEM::TYPE_CERTIFICATE_REQUEST, $pem->type());
    }

    /**
     * @depends toPEM
     *
     * @test
     */
    public function fromPEM(PEM $pem)
    {
        $cr = CertificationRequest::fromPEM($pem);
        static::assertInstanceOf(CertificationRequest::class, $cr);
        return $cr;
    }

    /**
     * @depends create
     * @depends fromPEM
     *
     * @test
     */
    public function pEMRecoded(CertificationRequest $ref, CertificationRequest $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @test
     */
    public function fromInvalidPEMFail()
    {
        $this->expectException(UnexpectedValueException::class);
        CertificationRequest::fromPEM(PEM::create('nope', ''));
    }
}
