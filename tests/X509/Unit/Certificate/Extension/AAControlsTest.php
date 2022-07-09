<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\AAControlsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;

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
        static::assertInstanceOf(AAControlsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_AA_CONTROLS, $ext->oid());
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
        $ext = AAControlsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AAControlsExtension::class, $ext);
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
    public function pathLen(AAControlsExtension $ext)
    {
        static::assertEquals(3, $ext->pathLen());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function permitted(AAControlsExtension $ext)
    {
        static::assertEquals(['1.2.3.4'], $ext->permittedAttrs());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function excluded(AAControlsExtension $ext)
    {
        static::assertEquals(['1.2.3.5', '1.2.3.6'], $ext->excludedAttrs());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function unspecified(AAControlsExtension $ext)
    {
        static::assertFalse($ext->permitUnspecified());
    }

    /**
     * @test
     */
    public function createEmpty()
    {
        $ext = new AAControlsExtension(false);
        static::assertInstanceOf(AAControlsExtension::class, $ext);
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
        static::assertInstanceOf(Sequence::class, $seq);
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
        static::assertInstanceOf(AAControlsExtension::class, $ext);
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
        static::assertEquals($ref, $new);
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
