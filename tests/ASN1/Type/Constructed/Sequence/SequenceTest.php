<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Constructed\Sequence;

use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Structure;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class SequenceTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $seq = new Sequence(new NullType(), new Boolean(true));
        static::assertInstanceOf(Structure::class, $seq);
        return $seq;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_SEQUENCE, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(string $data): Sequence
    {
        $el = Sequence::fromDER($data);
        static::assertInstanceOf(Sequence::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function elements(Sequence $seq)
    {
        $elements = $seq->elements();
        static::assertContainsOnlyInstancesOf(UnspecifiedType::class, $elements);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Sequence $seq)
    {
        static::assertCount(2, $seq);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(Sequence $seq)
    {
        $elements = [];
        foreach ($seq as $el) {
            $elements[] = $el;
        }
        static::assertCount(2, $elements);
        static::assertContainsOnlyInstancesOf(UnspecifiedType::class, $elements);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function atMethod(Sequence $seq): void
    {
        $el = $seq->at(0)
            ->asNull();
        static::assertInstanceOf(NullType::class, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function atExpected(Sequence $seq)
    {
        $el = $seq->at(0)
            ->asNull();
        static::assertInstanceOf(NullType::class, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function atOOB(Sequence $seq)
    {
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Structure doesn\'t have an element at index 2');
        $seq->at(2);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        static::assertInstanceOf(Sequence::class, $wrap->asSequence());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('SEQUENCE expected, got primitive NULL');
        $wrap->asSequence();
    }
}
