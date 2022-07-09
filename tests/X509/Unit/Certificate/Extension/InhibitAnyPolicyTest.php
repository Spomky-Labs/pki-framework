<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\InhibitAnyPolicyExtension;
use Sop\X509\Certificate\Extensions;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class InhibitAnyPolicyTest extends TestCase
{
    public function testCreate()
    {
        $ext = new InhibitAnyPolicyExtension(true, 3);
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_INHIBIT_ANY_POLICY, $ext->oid());
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
        $ext = InhibitAnyPolicyExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
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
    public function testSkipCerts(InhibitAnyPolicyExtension $ext)
    {
        $this->assertEquals(3, $ext->skipCerts());
    }

    /**
     * @depends testCreate
     */
    public function testExtensions(InhibitAnyPolicyExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasInhibitAnyPolicy());
        return $extensions;
    }

    /**
     * @depends testExtensions
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->inhibitAnyPolicy();
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
    }
}
