<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\ExtendedKeyUsageExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extensions;

/**
 * @internal
 */
final class ExtendedKeyUsageTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $ext = new ExtendedKeyUsageExtension(
            true,
            ExtendedKeyUsageExtension::OID_SERVER_AUTH,
            ExtendedKeyUsageExtension::OID_CLIENT_AUTH
        );
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_EXT_KEY_USAGE, $ext->oid());
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
        $ext = ExtendedKeyUsageExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
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
    public function has(ExtendedKeyUsageExtension $ext)
    {
        $this->assertTrue(
            $ext->has(ExtendedKeyUsageExtension::OID_SERVER_AUTH, ExtendedKeyUsageExtension::OID_CLIENT_AUTH)
        );
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNot(ExtendedKeyUsageExtension $ext)
    {
        $this->assertFalse($ext->has(ExtendedKeyUsageExtension::OID_TIME_STAMPING));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function purposes(ExtendedKeyUsageExtension $ext)
    {
        $this->assertContainsOnly('string', $ext->purposes());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(ExtendedKeyUsageExtension $ext)
    {
        $this->assertCount(2, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(ExtendedKeyUsageExtension $ext)
    {
        $values = [];
        foreach ($ext as $oid) {
            $values[] = $oid;
        }
        $this->assertContainsOnly('string', $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(ExtendedKeyUsageExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasExtendedKeyUsage());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->extendedKeyUsage();
        $this->assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
    }
}
