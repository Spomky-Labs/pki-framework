<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use SpomkyLabs\Pki\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

/**
 * @internal
 */
final class AuthorityKeyIdentifierTest extends RefExtTestHelper
{
    #[Test]
    public function authorityKeyIdentifier(): AuthorityKeyIdentifierExtension
    {
        $ext = self::$_extensions->authorityKeyIdentifier();
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('authorityKeyIdentifier')]
    public function authorityKeyIdentifierKey(AuthorityKeyIdentifierExtension $aki)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-interm-rsa.pem');
        $keyid = RSAPrivateKey::fromPEM($pem)->publicKey()
            ->publicKeyInfo()
            ->keyIdentifier();
        static::assertSame($keyid, $aki->keyIdentifier());
    }

    #[Test]
    #[Depends('authorityKeyIdentifier')]
    public function authorityKeyIdentifierIssuer(AuthorityKeyIdentifierExtension $aki)
    {
        $issuer_dn = $aki->issuer()
            ->firstOf(GeneralName::TAG_DIRECTORY_NAME)
            ->dn()
            ->toString();
        static::assertSame('o=ACME Ltd.,c=FI,cn=ACME Root CA', $issuer_dn);
        static::assertSame('1', $aki->serial());
    }
}
