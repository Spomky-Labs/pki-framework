<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
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

    final public const SERIAL = 42;

    private static $_issuer;

    public static function setUpBeforeClass(): void
    {
        self::$_issuer = GeneralNames::create(DirectoryName::create(Name::fromString('cn=Issuer')));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuer = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $ext = new AuthorityKeyIdentifierExtension(true, self::KEY_ID, self::$_issuer, self::SERIAL);
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    /**
     * @test
     */
    public function fromPKI()
    {
        $pki = PublicKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem'));
        $ext = AuthorityKeyIdentifierExtension::fromPublicKeyInfo($pki);
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_AUTHORITY_KEY_IDENTIFIER, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        static::assertTrue($ext->isCritical());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $ext = AuthorityKeyIdentifierExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyIdentifier(AuthorityKeyIdentifierExtension $ext)
    {
        static::assertEquals(self::KEY_ID, $ext->keyIdentifier());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function issuer(AuthorityKeyIdentifierExtension $ext)
    {
        static::assertEquals(self::$_issuer, $ext->issuer());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function serial(AuthorityKeyIdentifierExtension $ext)
    {
        static::assertEquals(self::SERIAL, $ext->serial());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(AuthorityKeyIdentifierExtension $ext)
    {
        $extensions = new Extensions($ext);
        static::assertTrue($extensions->hasAuthorityKeyIdentifier());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->authorityKeyIdentifier();
        static::assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
    }

    /**
     * @test
     */
    public function decodeIssuerXorSerialFail()
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

    /**
     * @test
     */
    public function encodeIssuerXorSerialFail()
    {
        $ext = new AuthorityKeyIdentifierExtension(false, '', null, 1);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    /**
     * @test
     */
    public function noKeyIdentifierFail()
    {
        $ext = new AuthorityKeyIdentifierExtension(false, null);
        $this->expectException(LogicException::class);
        $ext->keyIdentifier();
    }

    /**
     * @test
     */
    public function noIssuerFail()
    {
        $ext = new AuthorityKeyIdentifierExtension(false, null);
        $this->expectException(LogicException::class);
        $ext->issuer();
    }

    /**
     * @test
     */
    public function noSerialFail()
    {
        $ext = new AuthorityKeyIdentifierExtension(false, null);
        $this->expectException(LogicException::class);
        $ext->serial();
    }
}
