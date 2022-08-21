<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;

/**
 * @internal
 */
final class BasicConstraintsTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $ext = new BasicConstraintsExtension(true, true, 3);
        static::assertInstanceOf(BasicConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_BASIC_CONSTRAINTS, $ext->oid());
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
        $ext = BasicConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(BasicConstraintsExtension::class, $ext);
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
    public function cA(BasicConstraintsExtension $ext)
    {
        static::assertTrue($ext->isCA());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function pathLen(BasicConstraintsExtension $ext)
    {
        static::assertEquals(3, $ext->pathLen());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(BasicConstraintsExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasBasicConstraints());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->basicConstraints();
        static::assertInstanceOf(BasicConstraintsExtension::class, $ext);
    }

    /**
     * @test
     */
    public function noPathLenFail()
    {
        $ext = new BasicConstraintsExtension(false, false);
        $this->expectException(LogicException::class);
        $ext->pathLen();
    }
}
