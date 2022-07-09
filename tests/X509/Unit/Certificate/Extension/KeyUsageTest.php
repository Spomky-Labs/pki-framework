<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\KeyUsageExtension;
use Sop\X509\Certificate\Extensions;

/**
 * @internal
 */
final class KeyUsageTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $ext = new KeyUsageExtension(
            true,
            KeyUsageExtension::DIGITAL_SIGNATURE |
            KeyUsageExtension::KEY_ENCIPHERMENT
        );
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_KEY_USAGE, $ext->oid());
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
        $ext = KeyUsageExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
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
    public function digitalSignature(KeyUsageExtension $ext)
    {
        $this->assertTrue($ext->isDigitalSignature());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function nonRepudiation(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isNonRepudiation());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyEncipherment(KeyUsageExtension $ext)
    {
        $this->assertTrue($ext->isKeyEncipherment());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function dataEncipherment(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isDataEncipherment());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyAgreement(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isKeyAgreement());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyCertSign(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isKeyCertSign());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function cRLSign(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isCRLSign());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encipherOnly(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isEncipherOnly());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function decipherOnly(KeyUsageExtension $ext)
    {
        $this->assertFalse($ext->isDecipherOnly());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(KeyUsageExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasKeyUsage());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->keyUsage();
        $this->assertInstanceOf(KeyUsageExtension::class, $ext);
    }
}
