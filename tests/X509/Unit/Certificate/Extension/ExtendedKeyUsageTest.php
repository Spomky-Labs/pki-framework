<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): ExtendedKeyUsageExtension
    {
        $ext = ExtendedKeyUsageExtension::create(
            true,
            ExtendedKeyUsageExtension::OID_SERVER_AUTH,
            ExtendedKeyUsageExtension::OID_CLIENT_AUTH
        );
        static::assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_EXT_KEY_USAGE, $ext->oid());
    }

    #[Test]
    #[Depends('create')]
    public function critical(Extension $ext)
    {
        static::assertTrue($ext->isCritical());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $ext = ExtendedKeyUsageExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function has(ExtendedKeyUsageExtension $ext)
    {
        static::assertTrue(
            $ext->has(ExtendedKeyUsageExtension::OID_SERVER_AUTH, ExtendedKeyUsageExtension::OID_CLIENT_AUTH)
        );
    }

    #[Test]
    #[Depends('create')]
    public function hasNot(ExtendedKeyUsageExtension $ext)
    {
        static::assertFalse($ext->has(ExtendedKeyUsageExtension::OID_TIME_STAMPING));
    }

    #[Test]
    #[Depends('create')]
    public function purposes(ExtendedKeyUsageExtension $ext)
    {
        static::assertContainsOnly('string', $ext->purposes());
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(ExtendedKeyUsageExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(ExtendedKeyUsageExtension $ext)
    {
        $values = [];
        foreach ($ext as $oid) {
            $values[] = $oid;
        }
        static::assertContainsOnly('string', $values);
    }

    #[Test]
    #[Depends('create')]
    public function extensions(ExtendedKeyUsageExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasExtendedKeyUsage());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->extendedKeyUsage();
        static::assertInstanceOf(ExtendedKeyUsageExtension::class, $ext);
    }
}
