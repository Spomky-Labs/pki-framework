<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed;

use Iterator;
use OutOfBoundsException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    #[DataProvider('hasProvider')]
    public function has(int $idx, bool $result)
    {
        $seq = Sequence::create(NullType::create(), Boolean::create(true), NullType::create());
        static::assertSame($seq->has($idx), $result);
    }

    public static function hasProvider(): Iterator
    {
        yield [0, true];
        yield [1, true];
        yield [2, true];
        yield [3, false];
    }

    #[Test]
    #[DataProvider('hasTypeProvider')]
    public function hasType(int $idx, int $type, bool $result)
    {
        $seq = Sequence::create(NullType::create(), Boolean::create(true));
        static::assertSame($seq->has($idx, $type), $result);
    }

    public static function hasTypeProvider(): Iterator
    {
        yield [0, Element::TYPE_NULL, true];
        yield [0, Element::TYPE_INTEGER, false];
        yield [1, Element::TYPE_BOOLEAN, true];
        yield [2, Element::TYPE_NULL, false];
    }

    #[Test]
    public function explode()
    {
        $el = Sequence::create(NullType::create(), NullType::create(), NullType::create());
        $der = $el->toDER();
        $parts = Structure::explodeDER($der);
        $null = "\x5\x0";
        static::assertSame([$null, $null, $null], $parts);
    }

    #[Test]
    public function explodePrimitiveFail()
    {
        $el = NullType::create();
        $der = $el->toDER();
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('not constructed');
        Structure::explodeDER($der);
    }

    #[Test]
    public function explodeIndefiniteFail()
    {
        $el = Sequence::create(NullType::create());
        $el = $el->withIndefiniteLength();
        $der = $el->toDER();
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('not implemented');
        Structure::explodeDER($der);
    }

    #[Test]
    public function replace()
    {
        $seq = Sequence::create(NullType::create(), NullType::create());
        $seq = $seq->withReplaced(1, Boolean::create(true));
        $expected = Sequence::create(NullType::create(), Boolean::create(true));
        static::assertEquals($expected, $seq);
    }

    #[Test]
    public function replaceFail()
    {
        $seq = Sequence::create(NullType::create(), NullType::create());
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Structure doesn\'t have element at index 2');
        $seq->withReplaced(2, Boolean::create(true));
    }

    #[Test]
    public function insertFirst()
    {
        $seq = Sequence::create(NullType::create(), NullType::create());
        $seq = $seq->withInserted(0, Boolean::create(true));
        $expected = Sequence::create(Boolean::create(true), NullType::create(), NullType::create());
        static::assertEquals($expected, $seq);
    }

    #[Test]
    public function insertBetween()
    {
        $seq = Sequence::create(NullType::create(), NullType::create());
        $seq = $seq->withInserted(1, Boolean::create(true));
        $expected = Sequence::create(NullType::create(), Boolean::create(true), NullType::create());
        static::assertEquals($expected, $seq);
    }

    #[Test]
    public function insertLast()
    {
        $seq = Sequence::create(NullType::create(), NullType::create());
        $seq = $seq->withInserted(2, Boolean::create(true));
        $expected = Sequence::create(NullType::create(), NullType::create(), Boolean::create(true));
        static::assertEquals($expected, $seq);
    }

    #[Test]
    public function insertOOB()
    {
        $seq = Sequence::create(NullType::create(), NullType::create());
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Index 3 is out of bounds');
        $seq->withInserted(3, Boolean::create(true));
    }

    #[Test]
    public function append()
    {
        $seq = Sequence::create(NullType::create());
        $seq = $seq->withAppended(Boolean::create(true));
        $expected = Sequence::create(NullType::create(), Boolean::create(true));
        static::assertEquals($expected, $seq);
    }

    #[Test]
    public function prepend()
    {
        $seq = Sequence::create(NullType::create());
        $seq = $seq->withPrepended(Boolean::create(true));
        $expected = Sequence::create(Boolean::create(true), NullType::create());
        static::assertEquals($expected, $seq);
    }

    #[Test]
    public function removeFirst()
    {
        $seq = Sequence::create(NullType::create(), Boolean::create(true), NullType::create());
        $seq = $seq->withoutElement(0);
        $expected = Sequence::create(Boolean::create(true), NullType::create());
        static::assertEquals($expected, $seq);
    }

    #[Test]
    public function removeLast()
    {
        $seq = Sequence::create(NullType::create(), Boolean::create(true), NullType::create());
        $seq = $seq->withoutElement(2);
        $expected = Sequence::create(NullType::create(), Boolean::create(true));
        static::assertEquals($expected, $seq);
    }

    #[Test]
    public function removeOnly()
    {
        $seq = Sequence::create(NullType::create());
        $seq = $seq->withoutElement(0);
        $expected = Sequence::create();
        static::assertEquals($expected, $seq);
    }

    #[Test]
    public function removeFail()
    {
        $seq = Sequence::create(NullType::create());
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Structure doesn\'t have element at index 1');
        $seq->withoutElement(1);
    }

    /**
     * Test that cached tagging lookup table is cleared on clone.
     */
    #[Test]
    public function taggedAfterClone()
    {
        $seq = Sequence::create(ImplicitlyTaggedType::create(1, NullType::create()));
        $seq->hasTagged(1);
        $seq = $seq->withAppended(ImplicitlyTaggedType::create(2, NullType::create()));
        static::assertTrue($seq->hasTagged(2));
    }
}
