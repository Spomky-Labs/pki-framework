<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeAc;

use AlgorithmIdentifier;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificate;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * Decodes reference attribute certificate acme-ac.pem.
 *
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @return PEM
     */
    #[Test]
    public function pEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ac/acme-ac.pem');
        static::assertEquals(PEM::TYPE_ATTRIBUTE_CERTIFICATE, $pem->type());
        return $pem;
    }

    /**
     * @return AttributeCertificate
     */
    #[Test]
    #[Depends('pEM')]
    public function aC(PEM $pem)
    {
        $seq = Sequence::fromDER($pem->data());
        $ac = AttributeCertificate::fromASN1($seq);
        static::assertInstanceOf(AttributeCertificate::class, $ac);
        return $ac;
    }

    /**
     * @return AttributeCertificateInfo
     */
    #[Test]
    #[Depends('aC')]
    public function aCI(AttributeCertificate $ac)
    {
        $aci = $ac->acinfo();
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    /**
     * @return AlgorithmIdentifier
     */
    #[Test]
    #[Depends('aC')]
    public function signatureAlgo(AttributeCertificate $ac)
    {
        $algo = $ac->signatureAlgorithm();
        static::assertInstanceOf(SHA256WithRSAEncryptionAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    #[Test]
    #[Depends('aC')]
    public function verifySignature(AttributeCertificate $ac)
    {
        $cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        $pubkey_info = $cert->tbsCertificate()
            ->subjectPublicKeyInfo();
        static::assertTrue($ac->verify($pubkey_info));
    }
}
