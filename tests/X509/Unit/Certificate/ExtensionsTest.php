<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\DERData;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\UnknownExtension;
use Sop\X509\Certificate\Extensions;

/**
 * @internal
 */
final class ExtensionsTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $exts = new Extensions(
            new UnknownExtension('1.3.6.1.3.1', true, new DERData("\x05\x00")),
            new UnknownExtension('1.3.6.1.3.2', true, new DERData("\x05\x00"))
        );
        static::assertInstanceOf(Extensions::class, $exts);
        return $exts;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extensions $exts)
    {
        $seq = $exts->toASN1();
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
        $exts = Extensions::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Extensions::class, $exts);
        return $exts;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Extensions $ref, Extensions $new)
    {
        static::assertEquals($ref->toASN1(), $new->toASN1());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function has(Extensions $exts)
    {
        static::assertTrue($exts->has('1.3.6.1.3.1'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNot(Extensions $exts)
    {
        static::assertFalse($exts->has('1.3.6.1.3.3'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function get(Extensions $exts)
    {
        static::assertInstanceOf(Extension::class, $exts->get('1.3.6.1.3.1'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function getFail(Extensions $exts)
    {
        $this->expectException(LogicException::class);
        $exts->get('1.3.6.1.3.3');
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Extensions $exts)
    {
        static::assertCount(2, $exts);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(Extensions $exts)
    {
        $values = [];
        foreach ($exts as $ext) {
            $values[] = $ext;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(Extension::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withExtensions(Extensions $exts)
    {
        static $oid = '1.3.6.1.3.3';
        $exts = $exts->withExtensions(new UnknownExtension($oid, true, new DERData("\x05\x00")));
        static::assertTrue($exts->has($oid));
    }
}
