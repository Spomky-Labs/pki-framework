<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): BasicConstraintsExtension
    {
        $ext = BasicConstraintsExtension::create(true, true, 3);
        static::assertInstanceOf(BasicConstraintsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_BASIC_CONSTRAINTS, $ext->oid());
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
        $ext = BasicConstraintsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(BasicConstraintsExtension::class, $ext);
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
    public function cA(BasicConstraintsExtension $ext)
    {
        static::assertTrue($ext->isCA());
    }

    #[Test]
    #[Depends('create')]
    public function pathLen(BasicConstraintsExtension $ext)
    {
        static::assertSame(3, $ext->pathLen());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(BasicConstraintsExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasBasicConstraints());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->basicConstraints();
        static::assertInstanceOf(BasicConstraintsExtension::class, $ext);
    }

    #[Test]
    public function noPathLenFail()
    {
        $ext = BasicConstraintsExtension::create(false, false);
        $this->expectException(LogicException::class);
        $ext->pathLen();
    }
}
