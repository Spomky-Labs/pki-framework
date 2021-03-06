<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed;

use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Structure;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;

/**
 * @internal
 */
final class StructureTest extends TestCase
{
    /**
     * @dataProvider hasProvider
     *
     * @test
     */
    public function has(int $idx, bool $result)
    {
        $seq = Sequence::create(new NullType(), new Boolean(true), new NullType());
        static::assertEquals($seq->has($idx), $result);
    }

    public function hasProvider(): array
    {
        return [[0, true], [1, true], [2, true], [3, false]];
    }

    /**
     * @dataProvider hasTypeProvider
     *
     * @test
     */
    public function hasType(int $idx, int $type, bool $result)
    {
        $seq = Sequence::create(new NullType(), new Boolean(true));
        static::assertEquals($seq->has($idx, $type), $result);
    }

    public function hasTypeProvider(): array
    {
        return [
            [0, Element::TYPE_NULL, true],
            [0, Element::TYPE_INTEGER, false],
            [1, Element::TYPE_BOOLEAN, true],
            [2, Element::TYPE_NULL, false],
        ];
    }

    /**
     * @test
     */
    public function explode()
    {
        $el = Sequence::create(new NullType(), new NullType(), new NullType());
        $der = $el->toDER();
        $parts = Structure::explodeDER($der);
        $null = "\x5\x0";
        static::assertEquals([$null, $null, $null], $parts);
    }

    /**
     * @test
     */
    public function explodePrimitiveFail()
    {
        $el = new NullType();
        $der = $el->toDER();
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('not constructed');
        Structure::explodeDER($der);
    }

    /**
     * @test
     */
    public function explodeIndefiniteFail()
    {
        $el = Sequence::create(new NullType());
        $el = $el->withIndefiniteLength();
        $der = $el->toDER();
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('not implemented');
        Structure::explodeDER($der);
    }

    /**
     * @test
     */
    public function replace()
    {
        $seq = Sequence::create(new NullType(), new NullType());
        $seq = $seq->withReplaced(1, new Boolean(true));
        $expected = Sequence::create(new NullType(), new Boolean(true));
        static::assertEquals($expected, $seq);
    }

    /**
     * @test
     */
    public function replaceFail()
    {
        $seq = Sequence::create(new NullType(), new NullType());
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Structure doesn\'t have element at index 2');
        $seq->withReplaced(2, new Boolean(true));
    }

    /**
     * @test
     */
    public function insertFirst()
    {
        $seq = Sequence::create(new NullType(), new NullType());
        $seq = $seq->withInserted(0, new Boolean(true));
        $expected = Sequence::create(new Boolean(true), new NullType(), new NullType());
        static::assertEquals($expected, $seq);
    }

    /**
     * @test
     */
    public function insertBetween()
    {
        $seq = Sequence::create(new NullType(), new NullType());
        $seq = $seq->withInserted(1, new Boolean(true));
        $expected = Sequence::create(new NullType(), new Boolean(true), new NullType());
        static::assertEquals($expected, $seq);
    }

    /**
     * @test
     */
    public function insertLast()
    {
        $seq = Sequence::create(new NullType(), new NullType());
        $seq = $seq->withInserted(2, new Boolean(true));
        $expected = Sequence::create(new NullType(), new NullType(), new Boolean(true));
        static::assertEquals($expected, $seq);
    }

    /**
     * @test
     */
    public function insertOOB()
    {
        $seq = Sequence::create(new NullType(), new NullType());
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Index 3 is out of bounds');
        $seq->withInserted(3, new Boolean(true));
    }

    /**
     * @test
     */
    public function append()
    {
        $seq = Sequence::create(new NullType());
        $seq = $seq->withAppended(new Boolean(true));
        $expected = Sequence::create(new NullType(), new Boolean(true));
        static::assertEquals($expected, $seq);
    }

    /**
     * @test
     */
    public function prepend()
    {
        $seq = Sequence::create(new NullType());
        $seq = $seq->withPrepended(new Boolean(true));
        $expected = Sequence::create(new Boolean(true), new NullType());
        static::assertEquals($expected, $seq);
    }

    /**
     * @test
     */
    public function removeFirst()
    {
        $seq = Sequence::create(new NullType(), new Boolean(true), new NullType());
        $seq = $seq->withoutElement(0);
        $expected = Sequence::create(new Boolean(true), new NullType());
        static::assertEquals($expected, $seq);
    }

    /**
     * @test
     */
    public function removeLast()
    {
        $seq = Sequence::create(new NullType(), new Boolean(true), new NullType());
        $seq = $seq->withoutElement(2);
        $expected = Sequence::create(new NullType(), new Boolean(true));
        static::assertEquals($expected, $seq);
    }

    /**
     * @test
     */
    public function removeOnly()
    {
        $seq = Sequence::create(new NullType());
        $seq = $seq->withoutElement(0);
        $expected = Sequence::create();
        static::assertEquals($expected, $seq);
    }

    /**
     * @test
     */
    public function removeFail()
    {
        $seq = Sequence::create(new NullType());
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Structure doesn\'t have element at index 1');
        $seq->withoutElement(1);
    }

    /**
     * Test that cached tagging lookup table is cleared on clone.
     *
     * @test
     */
    public function taggedAfterClone()
    {
        $seq = Sequence::create(new ImplicitlyTaggedType(1, new NullType()));
        $seq->hasTagged(1);
        $seq = $seq->withAppended(new ImplicitlyTaggedType(2, new NullType()));
        static::assertTrue($seq->hasTagged(2));
    }
}
