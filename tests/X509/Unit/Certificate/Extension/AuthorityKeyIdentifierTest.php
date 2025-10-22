<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use UnexpectedValueException;

/**
 * @internal
 */
final class AuthorityKeyIdentifierTest extends TestCase
{
    final public const KEY_ID = 'test-id';

    final public const SERIAL = '42';

    private static ?GeneralNames $_issuer;

    public static function setUpBeforeClass(): void
    {
        self::$_issuer = GeneralNames::create(DirectoryName::create(Name::fromString('cn=Issuer')));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuer = null;
    }

    #[Test]
    public function create(): AuthorityKeyIdentifierExtension
    {
        $ext = AuthorityKeyIdentifierExtension::create(true, self::KEY_ID, self::$_issuer, self::SERIAL);
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    #[Test]
    public function fromPKI(): void
    {
        $pki = PublicKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem'));
        $ext = AuthorityKeyIdentifierExtension::fromPublicKeyInfo($pki);
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext): void
    {
        static::assertSame(Extension::OID_AUTHORITY_KEY_IDENTIFIER, $ext->oid());
    }

    #[Test]
    #[Depends('create')]
    public function critical(Extension $ext): void
    {
        static::assertTrue($ext->isCritical());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Extension $ext): string
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): AuthorityKeyIdentifierExtension
    {
        $ext = AuthorityKeyIdentifierExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Extension $ref, Extension $new): void
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function keyIdentifier(AuthorityKeyIdentifierExtension $ext): void
    {
        static::assertSame(self::KEY_ID, $ext->keyIdentifier());
    }

    #[Test]
    #[Depends('create')]
    public function issuer(AuthorityKeyIdentifierExtension $ext): void
    {
        static::assertEquals(self::$_issuer, $ext->issuer());
    }

    #[Test]
    #[Depends('create')]
    public function serial(AuthorityKeyIdentifierExtension $ext): void
    {
        static::assertSame(self::SERIAL, $ext->serial());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(AuthorityKeyIdentifierExtension $ext): Extensions
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasAuthorityKeyIdentifier());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts): void
    {
        $ext = $exts->authorityKeyIdentifier();
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
    }

    #[Test]
    public function decodeIssuerXorSerialFail(): void
    {
        $seq = Sequence::create(
            ImplicitlyTaggedType::create(0, OctetString::create('')),
            ImplicitlyTaggedType::create(2, Integer::create(1))
        );
        $ext_seq = Sequence::create(
            ObjectIdentifier::create(Extension::OID_AUTHORITY_KEY_IDENTIFIER),
            OctetString::create($seq->toDER())
        );
        $this->expectException(UnexpectedValueException::class);
        AuthorityKeyIdentifierExtension::fromASN1($ext_seq);
    }

    #[Test]
    public function encodeIssuerXorSerialFail(): void
    {
        $ext = AuthorityKeyIdentifierExtension::create(false, '', null, '1');
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    #[Test]
    public function noKeyIdentifierFail(): void
    {
        $ext = AuthorityKeyIdentifierExtension::create(false, null);
        $this->expectException(LogicException::class);
        $ext->keyIdentifier();
    }

    #[Test]
    public function noIssuerFail(): void
    {
        $ext = AuthorityKeyIdentifierExtension::create(false, null);
        $this->expectException(LogicException::class);
        $ext->issuer();
    }

    #[Test]
    public function noSerialFail(): void
    {
        $ext = AuthorityKeyIdentifierExtension::create(false, null);
        $this->expectException(LogicException::class);
        $ext->serial();
    }
}
