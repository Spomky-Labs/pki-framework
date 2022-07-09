<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\IssuerAlternativeNameExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

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
        $ext = new IssuerAlternativeNameExtension(true, new GeneralNames(DirectoryName::fromDNString(self::DN)));
        $this->assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_ISSUER_ALT_NAME, $ext->oid());
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
        $ext = IssuerAlternativeNameExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
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
    public function name(IssuerAlternativeNameExtension $ext)
    {
        $this->assertEquals(self::DN, $ext->names() ->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(IssuerAlternativeNameExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasIssuerAlternativeName());
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
        $this->assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
    }
}
