<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\AAControlsExtension;
use Sop\X509\Certificate\Extension\Extension;

/**
 * @internal
 */
final class AAControlsTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $ext = new AAControlsExtension(true, 3, ['1.2.3.4'], ['1.2.3.5', '1.2.3.6'], false);
        $this->assertInstanceOf(AAControlsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_AA_CONTROLS, $ext->oid());
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
        $ext = AAControlsExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(AAControlsExtension::class, $ext);
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
    public function pathLen(AAControlsExtension $ext)
    {
        $this->assertEquals(3, $ext->pathLen());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function permitted(AAControlsExtension $ext)
    {
        $this->assertEquals(['1.2.3.4'], $ext->permittedAttrs());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function excluded(AAControlsExtension $ext)
    {
        $this->assertEquals(['1.2.3.5', '1.2.3.6'], $ext->excludedAttrs());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function unspecified(AAControlsExtension $ext)
    {
        $this->assertFalse($ext->permitUnspecified());
    }

    /**
     * @test
     */
    public function createEmpty()
    {
        $ext = new AAControlsExtension(false);
        $this->assertInstanceOf(AAControlsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function encodeEmpty(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encodeEmpty
     *
     * @param string $der
     *
     * @test
     */
    public function decodeEmpty($der)
    {
        $ext = AAControlsExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(AAControlsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends createEmpty
     * @depends decodeEmpty
     *
     * @test
     */
    public function recodedEmpty(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function noPathLenFail(AAControlsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->pathLen();
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function noPermittedAttrsFail(AAControlsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->permittedAttrs();
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function noExcludedAttrsFail(AAControlsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->excludedAttrs();
    }
}
