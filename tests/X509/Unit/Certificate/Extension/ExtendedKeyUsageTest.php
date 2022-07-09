<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\ExtendedKeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;

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
        static::assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_EXT_KEY_USAGE, $ext->oid());
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
        $ext = ExtendedKeyUsageExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
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
    public function has(ExtendedKeyUsageExtension $ext)
    {
        static::assertTrue(
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
        static::assertFalse($ext->has(ExtendedKeyUsageExtension::OID_TIME_STAMPING));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function purposes(ExtendedKeyUsageExtension $ext)
    {
        static::assertContainsOnly('string', $ext->purposes());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(ExtendedKeyUsageExtension $ext)
    {
        static::assertCount(2, $ext);
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
        static::assertContainsOnly('string', $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(ExtendedKeyUsageExtension $ext)
    {
        $extensions = new Extensions($ext);
        static::assertTrue($extensions->hasExtendedKeyUsage());
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
        static::assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
    }
}
