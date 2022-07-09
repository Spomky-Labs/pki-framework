<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\InhibitAnyPolicyExtension;
use Sop\X509\Certificate\Extensions;

/**
 * @internal
 */
final class InhibitAnyPolicyTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $ext = new InhibitAnyPolicyExtension(true, 3);
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_INHIBIT_ANY_POLICY, $ext->oid());
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
        $ext = InhibitAnyPolicyExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
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
    public function skipCerts(InhibitAnyPolicyExtension $ext)
    {
        $this->assertEquals(3, $ext->skipCerts());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(InhibitAnyPolicyExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasInhibitAnyPolicy());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->inhibitAnyPolicy();
        $this->assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
    }
}
