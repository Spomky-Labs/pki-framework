<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\Sequence;

use OutOfBoundsException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Structure;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class SequenceTest extends TestCase
{
    #[Test]
    public function create()
    {
        $seq = Sequence::create(NullType::create(), Boolean::create(true));
        static::assertInstanceOf(Structure::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_SEQUENCE, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $data): Sequence
    {
        $el = Sequence::fromDER($data);
        static::assertInstanceOf(Sequence::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    #[Test]
    #[Depends('create')]
    public function elements(Sequence $seq)
    {
        $elements = $seq->elements();
        static::assertContainsOnlyInstancesOf(UnspecifiedType::class, $elements);
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(Sequence $seq)
    {
        static::assertCount(2, $seq);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(Sequence $seq)
    {
        $elements = [];
        foreach ($seq as $el) {
            $elements[] = $el;
        }
        static::assertCount(2, $elements);
        static::assertContainsOnlyInstancesOf(UnspecifiedType::class, $elements);
    }

    #[Test]
    #[Depends('create')]
    public function atMethod(Sequence $seq): void
    {
        $el = $seq->at(0)
            ->asNull();
        static::assertInstanceOf(NullType::class, $el);
    }

    #[Test]
    #[Depends('create')]
    public function atExpected(Sequence $seq)
    {
        $el = $seq->at(0)
            ->asNull();
        static::assertInstanceOf(NullType::class, $el);
    }

    #[Test]
    #[Depends('create')]
    public function atOOB(Sequence $seq)
    {
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Structure doesn\'t have an element at index 2');
        $seq->at(2);
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(Sequence::class, $wrap->asSequence());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('SEQUENCE expected, got primitive NULL');
        $wrap->asSequence();
    }
}
