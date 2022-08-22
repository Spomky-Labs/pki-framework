<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\IssuerAlternativeNameExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class IssuerAlternativeNameTest extends TestCase
{
    final public const DN = 'cn=Alt name';

    /**
     * @test
     */
    public function create()
    {
        $ext = IssuerAlternativeNameExtension::create(
            true,
            GeneralNames::create(DirectoryName::fromDNString(self::DN))
        );
        static::assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_ISSUER_ALT_NAME, $ext->oid());
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
        $ext = IssuerAlternativeNameExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
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
    public function name(IssuerAlternativeNameExtension $ext)
    {
        static::assertEquals(self::DN, $ext->names()->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(IssuerAlternativeNameExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasIssuerAlternativeName());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->issuerAlternativeName();
        static::assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
    }
}
