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
 * @group certificate
 * @group extension
 *
 * @internal
 */
class IssuerAlternativeNameTest extends TestCase
{
    final const DN = 'cn=Alt name';

    public function testCreate()
    {
        $ext = new IssuerAlternativeNameExtension(true,
            new GeneralNames(DirectoryName::fromDNString(self::DN)));
        $this->assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_ISSUER_ALT_NAME, $ext->oid());
    }

    /**
     * @depends testCreate
     */
    public function testCritical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $ext = IssuerAlternativeNameExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testName(IssuerAlternativeNameExtension $ext)
    {
        $this->assertEquals(self::DN, $ext->names()
            ->firstDN());
    }

    /**
     * @depends testCreate
     */
    public function testExtensions(IssuerAlternativeNameExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasIssuerAlternativeName());
        return $extensions;
    }

    /**
     * @depends testExtensions
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->issuerAlternativeName();
        $this->assertInstanceOf(IssuerAlternativeNameExtension::class, $ext);
    }
}
