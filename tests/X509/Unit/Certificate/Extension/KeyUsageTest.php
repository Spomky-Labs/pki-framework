<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;

/**
 * @internal
 */
final class KeyUsageTest extends TestCase
{
    #[Test]
    public function create(): KeyUsageExtension
    {
        $ext = KeyUsageExtension::create(
            true,
            KeyUsageExtension::DIGITAL_SIGNATURE |
            KeyUsageExtension::KEY_ENCIPHERMENT
        );
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_KEY_USAGE, $ext->oid());
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
        $ext = KeyUsageExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
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
    public function digitalSignature(KeyUsageExtension $ext)
    {
        static::assertTrue($ext->isDigitalSignature());
    }

    #[Test]
    #[Depends('create')]
    public function nonRepudiation(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isNonRepudiation());
    }

    #[Test]
    #[Depends('create')]
    public function keyEncipherment(KeyUsageExtension $ext)
    {
        static::assertTrue($ext->isKeyEncipherment());
    }

    #[Test]
    #[Depends('create')]
    public function dataEncipherment(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isDataEncipherment());
    }

    #[Test]
    #[Depends('create')]
    public function keyAgreement(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isKeyAgreement());
    }

    #[Test]
    #[Depends('create')]
    public function keyCertSign(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isKeyCertSign());
    }

    #[Test]
    #[Depends('create')]
    public function cRLSign(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isCRLSign());
    }

    #[Test]
    #[Depends('create')]
    public function encipherOnly(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isEncipherOnly());
    }

    #[Test]
    #[Depends('create')]
    public function decipherOnly(KeyUsageExtension $ext)
    {
        static::assertFalse($ext->isDecipherOnly());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(KeyUsageExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasKeyUsage());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->keyUsage();
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
    }
}
