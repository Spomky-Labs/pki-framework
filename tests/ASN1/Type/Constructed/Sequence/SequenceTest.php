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
        $this->assertInstanceOf(Structure::class, $seq);
        return $seq;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_SEQUENCE, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
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
        $this->assertInstanceOf(Sequence::class, $el);
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
        $this->assertEquals($ref, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function elements(Sequence $seq)
    {
        $elements = $seq->elements();
        $this->assertContainsOnlyInstancesOf(UnspecifiedType::class, $elements);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Sequence $seq)
    {
        $this->assertCount(2, $seq);
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
        $this->assertCount(2, $elements);
        $this->assertContainsOnlyInstancesOf(UnspecifiedType::class, $elements);
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
        $this->assertInstanceOf(NullType::class, $el);
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
        $this->assertInstanceOf(NullType::class, $el);
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
        $this->assertInstanceOf(Sequence::class, $wrap->asSequence());
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
