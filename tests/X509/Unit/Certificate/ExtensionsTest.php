<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\DERData;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;

/**
 * @internal
 */
final class ExtensionsTest extends TestCase
{
    #[Test]
    public function create(): Extensions
    {
        $exts = Extensions::create(
            UnknownExtension::create('1.3.6.1.3.1', true, DERData::create("\x05\x00")),
            UnknownExtension::create('1.3.6.1.3.2', true, DERData::create("\x05\x00"))
        );
        static::assertInstanceOf(Extensions::class, $exts);
        return $exts;
    }

    #[Test]
    #[Depends('create')]
    public function encode(Extensions $exts): string
    {
        $seq = $exts->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): Extensions
    {
        $exts = Extensions::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Extensions::class, $exts);
        return $exts;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Extensions $ref, Extensions $new)
    {
        static::assertEquals($ref->toASN1(), $new->toASN1());
    }

    #[Test]
    #[Depends('create')]
    public function has(Extensions $exts)
    {
        static::assertTrue($exts->has('1.3.6.1.3.1'));
    }

    #[Test]
    #[Depends('create')]
    public function hasNot(Extensions $exts)
    {
        static::assertFalse($exts->has('1.3.6.1.3.3'));
    }

    #[Test]
    #[Depends('create')]
    public function get(Extensions $exts)
    {
        static::assertInstanceOf(Extension::class, $exts->get('1.3.6.1.3.1'));
    }

    #[Test]
    #[Depends('create')]
    public function getFail(Extensions $exts)
    {
        $this->expectException(LogicException::class);
        $exts->get('1.3.6.1.3.3');
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(Extensions $exts)
    {
        static::assertCount(2, $exts);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(Extensions $exts)
    {
        $values = [];
        foreach ($exts as $ext) {
            $values[] = $ext;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(Extension::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function withExtensions(Extensions $exts)
    {
        static $oid = '1.3.6.1.3.3';
        $exts = $exts->withExtensions(UnknownExtension::create($oid, true, DERData::create("\x05\x00")));
        static::assertTrue($exts->has($oid));
    }
}
