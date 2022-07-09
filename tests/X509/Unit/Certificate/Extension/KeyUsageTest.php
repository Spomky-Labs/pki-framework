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
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_KEY_USAGE, $ext->oid());
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
        $ext = KeyUsageExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
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
    public function digitalSignature(KeyUsageExtension $ext)
    {
        static::assertTrue($ext->isDigitalSignature());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function nonRepudiation(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isNonRepudiation());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyEncipherment(KeyUsageExtension $ext)
    {
        static::assertTrue($ext->isKeyEncipherment());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function dataEncipherment(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isDataEncipherment());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyAgreement(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isKeyAgreement());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function keyCertSign(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isKeyCertSign());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function cRLSign(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isCRLSign());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encipherOnly(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isEncipherOnly());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function decipherOnly(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isDecipherOnly());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(KeyUsageExtension $ext)
    {
        $extensions = new Extensions($ext);
        static::assertTrue($extensions->hasKeyUsage());
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
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
    }
}
