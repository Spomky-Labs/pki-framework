<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\SubjectKeyIdentifierExtension;

/**
 * @internal
 */
final class SubjectKeyIdentifierTest extends RefExtTestHelper
{
    /**
     * @return SubjectKeyIdentifierExtension
     *
     * @test
     */
    public function subjectKeyIdentifier()
    {
        $ext = self::$_extensions->get(Extension::OID_SUBJECT_KEY_IDENTIFIER);
        static::assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends subjectKeyIdentifier
     *
     * @test
     */
    public function subjectKeyIdentifierKey(SubjectKeyIdentifierExtension $ski)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem');
        $keyid = RSAPrivateKey::fromPEM($pem)->publicKey()
            ->publicKeyInfo()
            ->keyIdentifier();
        static::assertEquals($keyid, $ski->keyIdentifier());
    }
}
