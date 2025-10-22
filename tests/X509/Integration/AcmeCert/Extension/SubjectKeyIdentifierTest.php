<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectKeyIdentifierExtension;

/**
 * @internal
 */
final class SubjectKeyIdentifierTest extends RefExtTestHelper
{
    #[Test]
    public function subjectKeyIdentifier(): SubjectKeyIdentifierExtension
    {
        $ext = self::$_extensions->get(Extension::OID_SUBJECT_KEY_IDENTIFIER);
        static::assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('subjectKeyIdentifier')]
    public function subjectKeyIdentifierKey(SubjectKeyIdentifierExtension $ski)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem');
        $keyid = RSAPrivateKey::fromPEM($pem)->publicKey()
            ->publicKeyInfo()
            ->keyIdentifier();
        static::assertSame($keyid, $ski->keyIdentifier());
    }
}
