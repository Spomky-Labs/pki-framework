<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

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
    /**
     * @test
     */
    public function create()
    {
        $ext = new InhibitAnyPolicyExtension(true, 3);
        static::assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_INHIBIT_ANY_POLICY, $ext->oid());
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
        $ext = InhibitAnyPolicyExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
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
    public function skipCerts(InhibitAnyPolicyExtension $ext)
    {
        static::assertEquals(3, $ext->skipCerts());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(InhibitAnyPolicyExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasInhibitAnyPolicy());
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
        static::assertInstanceOf(InhibitAnyPolicyExtension::class, $ext);
    }
}
