<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert;

use DateTimeZone;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Signature\Signature;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;

/**
 * Decodes reference certificate acme-rsa.pem.
 *
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function cert(): Certificate
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem');
        $cert = Certificate::fromPEM($pem);
        static::assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    #[Test]
    #[Depends('cert')]
    public function tBSCertificate(Certificate $cert): TBSCertificate
    {
        $tbsCert = $cert->tbsCertificate();
        static::assertInstanceOf(TBSCertificate::class, $tbsCert);
        return $tbsCert;
    }

    /**
     * @return AlgorithmIdentifier
     */
    #[Test]
    #[Depends('cert')]
    public function signatureAlgorithm(Certificate $cert): SignatureAlgorithmIdentifier
    {
        $algo = $cert->signatureAlgorithm();
        static::assertInstanceOf(SignatureAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    #[Test]
    #[Depends('signatureAlgorithm')]
    public function signatureAlgorithmValue(AlgorithmIdentifier $algo)
    {
        static::assertSame(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, $algo->oid());
    }

    /**
     * @return Signature
     */
    #[Test]
    #[Depends('cert')]
    public function signature(Certificate $cert)
    {
        $signature = $cert->signatureValue();
        static::assertInstanceOf(Signature::class, $signature);
        return $signature;
    }

    #[Test]
    #[Depends('signature')]
    public function signatureValue(Signature $sig)
    {
        $expected = hex2bin(trim(file_get_contents(TEST_ASSETS_DIR . '/certs/acme-rsa.pem.sig')));
        static::assertEquals($expected, $sig->bitString()->string());
    }

    #[Test]
    #[Depends('tBSCertificate')]
    public function version(TBSCertificate $tbsCert)
    {
        static::assertSame(TBSCertificate::VERSION_3, $tbsCert->version());
    }

    #[Test]
    #[Depends('tBSCertificate')]
    public function serial(TBSCertificate $tbsCert)
    {
        static::assertSame('42', $tbsCert->serialNumber());
    }

    #[Test]
    #[Depends('tBSCertificate')]
    public function signatureAlgo(TBSCertificate $tbsCert)
    {
        static::assertSame(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, $tbsCert->signature()->oid());
    }

    /**
     * @return Name
     */
    #[Test]
    #[Depends('tBSCertificate')]
    public function issuer(TBSCertificate $tbsCert)
    {
        $issuer = $tbsCert->issuer();
        static::assertInstanceOf(Name::class, $issuer);
        return $issuer;
    }

    #[Test]
    #[Depends('issuer')]
    public function issuerDN(Name $name)
    {
        static::assertSame('o=ACME Ltd.,c=FI,cn=ACME Intermediate CA', $name->toString());
    }

    /**
     * @return Validity
     */
    #[Test]
    #[Depends('tBSCertificate')]
    public function validity(TBSCertificate $tbsCert)
    {
        $validity = $tbsCert->validity();
        static::assertInstanceOf(Validity::class, $validity);
        return $validity;
    }

    #[Test]
    #[Depends('validity')]
    public function notBefore(Validity $validity)
    {
        $str = $validity->notBefore()
            ->dateTime()
            ->setTimezone(new DateTimeZone('GMT'))
            ->format('M j H:i:s Y T');
        static::assertSame('Jan 1 12:00:00 2016 GMT', $str);
    }

    #[Test]
    #[Depends('validity')]
    public function notAfter(Validity $validity)
    {
        $str = $validity->notAfter()
            ->dateTime()
            ->setTimezone(new DateTimeZone('GMT'))
            ->format('M j H:i:s Y T');
        static::assertSame('Jan 2 15:04:05 2026 GMT', $str);
    }

    /**
     * @return Name
     */
    #[Test]
    #[Depends('tBSCertificate')]
    public function subject(TBSCertificate $tbsCert)
    {
        $subject = $tbsCert->subject();
        static::assertInstanceOf(Name::class, $subject);
        return $subject;
    }

    #[Test]
    #[Depends('subject')]
    public function subjectDN(Name $name)
    {
        static::assertSame('o=ACME Ltd.,c=FI,cn=example.com', $name->toString());
    }

    /**
     * @return PublicKeyInfo
     */
    #[Test]
    #[Depends('tBSCertificate')]
    public function subjectPublicKeyInfo(TBSCertificate $tbsCert)
    {
        $pki = $tbsCert->subjectPublicKeyInfo();
        static::assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    #[Test]
    #[Depends('subjectPublicKeyInfo')]
    public function publicKeyAlgo(PublicKeyInfo $pki)
    {
        static::assertSame(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $pki->algorithmIdentifier()->oid());
    }

    #[Test]
    #[Depends('subjectPublicKeyInfo')]
    public function publicKey(PublicKeyInfo $pki)
    {
        $pk = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->publicKey();
        static::assertEquals($pk, $pki->publicKey());
    }

    /**
     * @return Extensions
     */
    #[Test]
    #[Depends('tBSCertificate')]
    public function extensions(TBSCertificate $tbsCert)
    {
        $extensions = $tbsCert->extensions();
        static::assertInstanceOf(Extensions::class, $extensions);
        return $extensions;
    }
}
