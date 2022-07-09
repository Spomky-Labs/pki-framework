<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Csr;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Signature\Signature;
use Sop\X501\ASN1\Name;
use Sop\X509\CertificationRequest\CertificationRequest;
use Sop\X509\CertificationRequest\CertificationRequestInfo;
use UnexpectedValueException;

/**
 * @internal
 */
final class CertificationRequestTest extends TestCase
{
    private static $_subject;

    private static $_privateKeyInfo;

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
        $cri = new CertificationRequestInfo(self::$_subject, $pkinfo);
        $data = $cri->toASN1()
            ->toDER();
        $algo = new SHA256WithRSAEncryptionAlgorithmIdentifier();
        $signature = Crypto::getDefault()->sign($data, self::$_privateKeyInfo, $algo);
        $cr = new CertificationRequest($cri, $algo, $signature);
        $this->assertInstanceOf(CertificationRequest::class, $cr);
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
        $cr = CertificationRequest::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(CertificationRequest::class, $cr);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function certificationRequestInfo(CertificationRequest $cr)
    {
        $this->assertInstanceOf(CertificationRequestInfo::class, $cr->certificationRequestInfo());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function algo(CertificationRequest $cr)
    {
        $this->assertInstanceOf(SHA256WithRSAEncryptionAlgorithmIdentifier::class, $cr->signatureAlgorithm());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function signature(CertificationRequest $cr)
    {
        $this->assertInstanceOf(Signature::class, $cr->signature());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function verify(CertificationRequest $cr)
    {
        $this->assertTrue($cr->verify());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function invalidAlgoFail(CertificationRequest $cr)
    {
        $seq = $cr->toASN1();
        $algo = new GenericAlgorithmIdentifier('1.3.6.1.3');
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
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(CertificationRequest $cr)
    {
        $this->assertIsString(strval($cr));
    }

    /**
     * @depends toPEM
     *
     * @test
     */
    public function pEMType(PEM $pem)
    {
        $this->assertEquals(PEM::TYPE_CERTIFICATE_REQUEST, $pem->type());
    }

    /**
     * @depends toPEM
     *
     * @test
     */
    public function fromPEM(PEM $pem)
    {
        $cr = CertificationRequest::fromPEM($pem);
        $this->assertInstanceOf(CertificationRequest::class, $cr);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @test
     */
    public function fromInvalidPEMFail()
    {
        $this->expectException(UnexpectedValueException::class);
        CertificationRequest::fromPEM(new PEM('nope', ''));
    }
}
