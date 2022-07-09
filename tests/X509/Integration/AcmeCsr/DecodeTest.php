<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCsr;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Signature\Signature;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\KeyUsageExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use Sop\X509\CertificationRequest\Attributes;
use Sop\X509\CertificationRequest\CertificationRequest;
use Sop\X509\CertificationRequest\CertificationRequestInfo;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @return CertificationRequest
     *
     * @test
     */
    public function cSR()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.csr');
        $csr = CertificationRequest::fromPEM($pem);
        $this->assertInstanceOf(CertificationRequest::class, $csr);
        return $csr;
    }

    /**
     * @depends cSR
     *
     * @return CertificationRequestInfo
     *
     * @test
     */
    public function certificationRequestInfo(CertificationRequest $cr)
    {
        $cri = $cr->certificationRequestInfo();
        $this->assertInstanceOf(CertificationRequestInfo::class, $cri);
        return $cri;
    }

    /**
     * @depends cSR
     *
     * @return AlgorithmIdentifier
     *
     * @test
     */
    public function signatureAlgorithm(CertificationRequest $cr)
    {
        $algo = $cr->signatureAlgorithm();
        $this->assertInstanceOf(SignatureAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    /**
     * @depends signatureAlgorithm
     *
     * @test
     */
    public function algoType(AlgorithmIdentifier $algo)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, $algo->oid());
    }

    /**
     * @depends cSR
     *
     * @return Signature
     *
     * @test
     */
    public function signature(CertificationRequest $cr)
    {
        $signature = $cr->signature();
        $this->assertInstanceOf(Signature::class, $signature);
        return $signature;
    }

    /**
     * @depends signature
     *
     * @test
     */
    public function signatureValue(Signature $signature)
    {
        $expected = hex2bin(trim(file_get_contents(TEST_ASSETS_DIR . '/certs/acme-rsa.csr.sig')));
        $this->assertEquals($expected, $signature->bitString() ->string());
    }

    /**
     * @depends certificationRequestInfo
     *
     * @test
     */
    public function version(CertificationRequestInfo $cri)
    {
        $this->assertEquals(CertificationRequestInfo::VERSION_1, $cri->version());
    }

    /**
     * @depends certificationRequestInfo
     *
     * @return Name
     *
     * @test
     */
    public function subject(CertificationRequestInfo $cri)
    {
        $subject = $cri->subject();
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
     * @depends certificationRequestInfo
     *
     * @return PublicKeyInfo
     *
     * @test
     */
    public function subjectPKInfo(CertificationRequestInfo $cri)
    {
        $info = $cri->subjectPKInfo();
        $this->assertInstanceOf(PublicKeyInfo::class, $info);
        return $info;
    }

    /**
     * @depends subjectPKInfo
     *
     * @test
     */
    public function publicKeyAlgo(PublicKeyInfo $info)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $info->algorithmIdentifier() ->oid());
    }

    /**
     * @depends subjectPKInfo
     *
     * @test
     */
    public function publicKey(PublicKeyInfo $info)
    {
        $pk = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->publicKey();
        $this->assertEquals($pk, $info->publicKey());
    }

    /**
     * @depends certificationRequestInfo
     *
     * @return Attributes
     *
     * @test
     */
    public function attributes(CertificationRequestInfo $cri)
    {
        $this->assertTrue($cri->hasAttributes());
        $attribs = $cri->attributes();
        $this->assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @return ExtensionRequestValue
     *
     * @test
     */
    public function extensionRequestAttribute(Attributes $attribs)
    {
        $attr = ExtensionRequestValue::fromSelf($attribs->firstOf(ExtensionRequestValue::OID)->first());
        $this->assertInstanceOf(ExtensionRequestValue::class, $attr);
        return $attr;
    }

    /**
     * @depends extensionRequestAttribute
     *
     * @return Extensions
     *
     * @test
     */
    public function requestedExtensions(ExtensionRequestValue $attr)
    {
        $extensions = $attr->extensions();
        $this->assertInstanceOf(Extensions::class, $extensions);
        return $extensions;
    }

    /**
     * @depends requestedExtensions
     *
     * @return KeyUsageExtension
     *
     * @test
     */
    public function keyUsageExtension(Extensions $extensions)
    {
        $ext = $extensions->get(Extension::OID_KEY_USAGE);
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends keyUsageExtension
     *
     * @test
     */
    public function keyUsageExtensionValue(KeyUsageExtension $ext)
    {
        $this->assertTrue($ext->isKeyEncipherment());
        $this->assertTrue($ext->isKeyCertSign());
    }
}
