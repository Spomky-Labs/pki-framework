<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\BasicConstraintsExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extensions;

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
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_BASIC_CONSTRAINTS, $ext->oid());
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
        $ext = BasicConstraintsExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
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
    public function cA(BasicConstraintsExtension $ext)
    {
        $this->assertTrue($ext->isCA());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function pathLen(BasicConstraintsExtension $ext)
    {
        $this->assertEquals(3, $ext->pathLen());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(BasicConstraintsExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasBasicConstraints());
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
        $this->assertInstanceOf(BasicConstraintsExtension::class, $ext);
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
