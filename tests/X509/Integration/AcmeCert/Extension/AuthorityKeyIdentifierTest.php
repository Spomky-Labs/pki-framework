<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use SpomkyLabs\Pki\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

/**
 * @internal
 */
final class AuthorityKeyIdentifierTest extends RefExtTestHelper
{
    /**
     * @return AuthorityKeyIdentifierExtension
     *
     * @test
     */
    public function authorityKeyIdentifier()
    {
        $ext = self::$_extensions->authorityKeyIdentifier();
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends authorityKeyIdentifier
     *
     * @test
     */
    public function authorityKeyIdentifierKey(AuthorityKeyIdentifierExtension $aki)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-interm-rsa.pem');
        $keyid = RSAPrivateKey::fromPEM($pem)->publicKey()
            ->publicKeyInfo()
            ->keyIdentifier();
        static::assertEquals($keyid, $aki->keyIdentifier());
    }

    /**
     * @depends authorityKeyIdentifier
     *
     * @test
     */
    public function authorityKeyIdentifierIssuer(AuthorityKeyIdentifierExtension $aki)
    {
        $issuer_dn = $aki->issuer()
            ->firstOf(GeneralName::TAG_DIRECTORY_NAME)
            ->dn()
            ->toString();
        static::assertEquals('o=ACME Ltd.,c=FI,cn=ACME Root CA', $issuer_dn);
        static::assertEquals(1, $aki->serial());
    }
}
