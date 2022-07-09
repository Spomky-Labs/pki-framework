<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;
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
        self::$_issuer = new GeneralNames(new DirectoryName(Name::fromString('cn=Issuer')));
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
        $this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    /**
     * @test
     */
    public function fromPKI()
    {
        $pki = PublicKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem'));
        $ext = AuthorityKeyIdentifierExtension::fromPublicKeyInfo($pki);
        $this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_AUTHORITY_KEY_IDENTIFIER, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
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
        $this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyIdentifier(AuthorityKeyIdentifierExtension $ext)
    {
        $this->assertEquals(self::KEY_ID, $ext->keyIdentifier());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function issuer(AuthorityKeyIdentifierExtension $ext)
    {
        $this->assertEquals(self::$_issuer, $ext->issuer());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function serial(AuthorityKeyIdentifierExtension $ext)
    {
        $this->assertEquals(self::SERIAL, $ext->serial());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(AuthorityKeyIdentifierExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasAuthorityKeyIdentifier());
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
        $this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
    }

    /**
     * @test
     */
    public function decodeIssuerXorSerialFail()
    {
        $seq = new Sequence(
            new ImplicitlyTaggedType(0, new OctetString('')),
            new ImplicitlyTaggedType(2, new Integer(1))
        );
        $ext_seq = new Sequence(
            new ObjectIdentifier(Extension::OID_AUTHORITY_KEY_IDENTIFIER),
            new OctetString($seq->toDER())
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
