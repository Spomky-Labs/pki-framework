<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert;

use DateTimeZone;
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
    /**
     * @return Certificate
     *
     * @test
     */
    public function cert()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem');
        $cert = Certificate::fromPEM($pem);
        static::assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends cert
     *
     * @return TBSCertificate
     *
     * @test
     */
    public function tBSCertificate(Certificate $cert)
    {
        $tbsCert = $cert->tbsCertificate();
        static::assertInstanceOf(TBSCertificate::class, $tbsCert);
        return $tbsCert;
    }

    /**
     * @depends cert
     *
     * @return AlgorithmIdentifier
     *
     * @test
     */
    public function signatureAlgorithm(Certificate $cert)
    {
        $algo = $cert->signatureAlgorithm();
        static::assertInstanceOf(SignatureAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    /**
     * @depends signatureAlgorithm
     *
     * @test
     */
    public function signatureAlgorithmValue(AlgorithmIdentifier $algo)
    {
        static::assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, $algo->oid());
    }

    /**
     * @depends cert
     *
     * @return Signature
     *
     * @test
     */
    public function signature(Certificate $cert)
    {
        $signature = $cert->signatureValue();
        static::assertInstanceOf(Signature::class, $signature);
        return $signature;
    }

    /**
     * @depends signature
     *
     * @test
     */
    public function signatureValue(Signature $sig)
    {
        $expected = hex2bin(trim(file_get_contents(TEST_ASSETS_DIR . '/certs/acme-rsa.pem.sig')));
        static::assertEquals($expected, $sig->bitString() ->string());
    }

    /**
     * @depends tBSCertificate
     *
     * @test
     */
    public function version(TBSCertificate $tbsCert)
    {
        static::assertEquals(TBSCertificate::VERSION_3, $tbsCert->version());
    }

    /**
     * @depends tBSCertificate
     *
     * @test
     */
    public function serial(TBSCertificate $tbsCert)
    {
        static::assertEquals(42, $tbsCert->serialNumber());
    }

    /**
     * @depends tBSCertificate
     *
     * @test
     */
    public function signatureAlgo(TBSCertificate $tbsCert)
    {
        static::assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, $tbsCert->signature() ->oid());
    }

    /**
     * @depends tBSCertificate
     *
     * @return Name
     *
     * @test
     */
    public function issuer(TBSCertificate $tbsCert)
    {
        $issuer = $tbsCert->issuer();
        static::assertInstanceOf(Name::class, $issuer);
        return $issuer;
    }

    /**
     * @depends issuer
     *
     * @test
     */
    public function issuerDN(Name $name)
    {
        static::assertEquals('o=ACME Ltd.,c=FI,cn=ACME Intermediate CA', $name->toString());
    }

    /**
     * @depends tBSCertificate
     *
     * @return Validity
     *
     * @test
     */
    public function validity(TBSCertificate $tbsCert)
    {
        $validity = $tbsCert->validity();
        static::assertInstanceOf(Validity::class, $validity);
        return $validity;
    }

    /**
     * @depends validity
     *
     * @test
     */
    public function notBefore(Validity $validity)
    {
        $str = $validity->notBefore()
            ->dateTime()
            ->setTimezone(new DateTimeZone('GMT'))
            ->format('M j H:i:s Y T');
        static::assertEquals('Jan 1 12:00:00 2016 GMT', $str);
    }

    /**
     * @depends validity
     *
     * @test
     */
    public function notAfter(Validity $validity)
    {
        $str = $validity->notAfter()
            ->dateTime()
            ->setTimezone(new DateTimeZone('GMT'))
            ->format('M j H:i:s Y T');
        static::assertEquals('Jan 2 15:04:05 2026 GMT', $str);
    }

    /**
     * @depends tBSCertificate
     *
     * @return Name
     *
     * @test
     */
    public function subject(TBSCertificate $tbsCert)
    {
        $subject = $tbsCert->subject();
        static::assertInstanceOf(Name::class, $subject);
        return $subject;
    }

    /**
     * @depends subject
     *
     * @test
     */
    public function subjectDN(Name $name)
    {
        static::assertEquals('o=ACME Ltd.,c=FI,cn=example.com', $name->toString());
    }

    /**
     * @depends tBSCertificate
     *
     * @return PublicKeyInfo
     *
     * @test
     */
    public function subjectPublicKeyInfo(TBSCertificate $tbsCert)
    {
        $pki = $tbsCert->subjectPublicKeyInfo();
        static::assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends subjectPublicKeyInfo
     *
     * @test
     */
    public function publicKeyAlgo(PublicKeyInfo $pki)
    {
        static::assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $pki->algorithmIdentifier() ->oid());
    }

    /**
     * @depends subjectPublicKeyInfo
     *
     * @test
     */
    public function publicKey(PublicKeyInfo $pki)
    {
        $pk = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->publicKey();
        static::assertEquals($pk, $pki->publicKey());
    }

    /**
     * @depends tBSCertificate
     *
     * @return Extensions
     *
     * @test
     */
    public function extensions(TBSCertificate $tbsCert)
    {
        $extensions = $tbsCert->extensions();
        static::assertInstanceOf(Extensions::class, $extensions);
        return $extensions;
    }
}
