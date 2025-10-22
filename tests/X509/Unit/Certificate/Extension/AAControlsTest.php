<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\AAControlsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;

/**
 * @internal
 */
final class AAControlsTest extends TestCase
{
    #[Test]
    public function create(): AAControlsExtension
    {
        $ext = AAControlsExtension::create(true, 3, ['1.2.3.4'], ['1.2.3.5', '1.2.3.6'], false);
        static::assertInstanceOf(AAControlsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_AA_CONTROLS, $ext->oid());
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
        $ext = AAControlsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AAControlsExtension::class, $ext);
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
    public function pathLen(AAControlsExtension $ext)
    {
        static::assertSame(3, $ext->pathLen());
    }

    #[Test]
    #[Depends('decode')]
    public function permitted(AAControlsExtension $ext)
    {
        static::assertSame(['1.2.3.4'], $ext->permittedAttrs());
    }

    #[Test]
    #[Depends('decode')]
    public function excluded(AAControlsExtension $ext)
    {
        static::assertSame(['1.2.3.5', '1.2.3.6'], $ext->excludedAttrs());
    }

    #[Test]
    #[Depends('decode')]
    public function unspecified(AAControlsExtension $ext)
    {
        static::assertFalse($ext->permitUnspecified());
    }

    #[Test]
    public function createEmpty()
    {
        $ext = AAControlsExtension::create(false);
        static::assertInstanceOf(AAControlsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('createEmpty')]
    public function encodeEmpty(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encodeEmpty')]
    public function decodeEmpty($der)
    {
        $ext = AAControlsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AAControlsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('createEmpty')]
    #[Depends('decodeEmpty')]
    public function recodedEmpty(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createEmpty')]
    public function noPathLenFail(AAControlsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->pathLen();
    }

    #[Test]
    #[Depends('createEmpty')]
    public function noPermittedAttrsFail(AAControlsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->permittedAttrs();
    }

    #[Test]
    #[Depends('createEmpty')]
    public function noExcludedAttrsFail(AAControlsExtension $ext)
    {
        $this->expectException(LogicException::class);
        $ext->excludedAttrs();
    }
}
