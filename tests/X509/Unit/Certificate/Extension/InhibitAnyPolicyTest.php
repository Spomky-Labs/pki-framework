<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\InhibitAnyPolicyExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;

/**
 * @internal
 */
final class InhibitAnyPolicyTest extends TestCase
{
    #[Test]
    public function create(): InhibitAnyPolicyExtension
    {
        $ext = InhibitAnyPolicyExtension::create(true, 3);
        static::assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_INHIBIT_ANY_POLICY, $ext->oid());
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
        $ext = InhibitAnyPolicyExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
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
    public function skipCerts(InhibitAnyPolicyExtension $ext)
    {
        static::assertSame(3, $ext->skipCerts());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(InhibitAnyPolicyExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasInhibitAnyPolicy());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->inhibitAnyPolicy();
        static::assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
    }
}
