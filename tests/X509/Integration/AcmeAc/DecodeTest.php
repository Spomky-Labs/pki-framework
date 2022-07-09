<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeAc;

use AlgorithmIdentifier;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\X509\AttributeCertificate\AttributeCertificate;
use Sop\X509\AttributeCertificate\AttributeCertificateInfo;
use Sop\X509\Certificate\Certificate;

/**
 * Decodes reference attribute certificate acme-ac.pem.
 *
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @return PEM
     *
     * @test
     */
    public function pEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ac/acme-ac.pem');
        $this->assertEquals(PEM::TYPE_ATTRIBUTE_CERTIFICATE, $pem->type());
        return $pem;
    }

    /**
     * @depends pEM
     *
     * @return AttributeCertificate
     *
     * @test
     */
    public function aC(PEM $pem)
    {
        $seq = Sequence::fromDER($pem->data());
        $ac = AttributeCertificate::fromASN1($seq);
        $this->assertInstanceOf(AttributeCertificate::class, $ac);
        return $ac;
    }

    /**
     * @depends aC
     *
     * @return AttributeCertificateInfo
     *
     * @test
     */
    public function aCI(AttributeCertificate $ac)
    {
        $aci = $ac->acinfo();
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    /**
     * @depends aC
     *
     * @return AlgorithmIdentifier
     *
     * @test
     */
    public function signatureAlgo(AttributeCertificate $ac)
    {
        $algo = $ac->signatureAlgorithm();
        $this->assertInstanceOf(SHA256WithRSAEncryptionAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    /**
     * @depends aC
     *
     * @test
     */
    public function verifySignature(AttributeCertificate $ac)
    {
        $cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        $pubkey_info = $cert->tbsCertificate()
            ->subjectPublicKeyInfo();
        $this->assertTrue($ac->verify($pubkey_info));
    }
}
