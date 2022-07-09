<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert;

use DateTimeZone;
use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Signature\Signature;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\Extensions;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\Validity;

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
        $this->assertInstanceOf(Certificate::class, $cert);
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
        $this->assertInstanceOf(TBSCertificate::class, $tbsCert);
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
        $this->assertInstanceOf(SignatureAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    /**
     * @depends signatureAlgorithm
     *
     * @test
     */
    public function signatureAlgorithmValue(AlgorithmIdentifier $algo)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, $algo->oid());
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
        $this->assertInstanceOf(Signature::class, $signature);
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
        $this->assertEquals($expected, $sig->bitString() ->string());
    }

    /**
     * @depends tBSCertificate
     *
     * @test
     */
    public function version(TBSCertificate $tbsCert)
    {
        $this->assertEquals(TBSCertificate::VERSION_3, $tbsCert->version());
    }

    /**
     * @depends tBSCertificate
     *
     * @test
     */
    public function serial(TBSCertificate $tbsCert)
    {
        $this->assertEquals(42, $tbsCert->serialNumber());
    }

    /**
     * @depends tBSCertificate
     *
     * @test
     */
    public function signatureAlgo(TBSCertificate $tbsCert)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, $tbsCert->signature() ->oid());
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
        $this->assertInstanceOf(Name::class, $issuer);
        return $issuer;
    }

    /**
     * @depends issuer
     *
     * @test
     */
    public function issuerDN(Name $name)
    {
        $this->assertEquals('o=ACME Ltd.,c=FI,cn=ACME Intermediate CA', $name->toString());
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
        $this->assertInstanceOf(Validity::class, $validity);
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
        $this->assertEquals('Jan 1 12:00:00 2016 GMT', $str);
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
        $this->assertEquals('Jan 2 15:04:05 2026 GMT', $str);
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
        $this->assertInstanceOf(Name::class, $subject);
        return $subject;
    }

    /**
     * @depends subject
     *
     * @test
     */
    public function subjectDN(Name $name)
    {
        $this->assertEquals('o=ACME Ltd.,c=FI,cn=example.com', $name->toString());
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
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends subjectPublicKeyInfo
     *
     * @test
     */
    public function publicKeyAlgo(PublicKeyInfo $pki)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $pki->algorithmIdentifier() ->oid());
    }

    /**
     * @depends subjectPublicKeyInfo
     *
     * @test
     */
    public function publicKey(PublicKeyInfo $pki)
    {
        $pk = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->publicKey();
        $this->assertEquals($pk, $pki->publicKey());
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
        $this->assertInstanceOf(Extensions::class, $extensions);
        return $extensions;
    }
}
