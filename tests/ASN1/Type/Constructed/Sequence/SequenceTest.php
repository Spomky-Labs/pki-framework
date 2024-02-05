<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\Sequence;

use OutOfBoundsException;
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
    public function create(): void
    {
        $seq = Sequence::create(NullType::create(), Boolean::create(true));
        static::assertInstanceOf(Structure::class, $seq);
        static::assertSame(Element::TYPE_SEQUENCE, $seq->tag());
        static::assertContainsOnlyInstancesOf(UnspecifiedType::class, $seq->elements());
        static::assertCount(2, $seq);
        $elements = [];
        foreach ($seq as $el) {
            $elements[] = $el;
        }
        static::assertCount(2, $elements);
        static::assertContainsOnlyInstancesOf(UnspecifiedType::class, $elements);
        $el = $seq->at(0)
            ->asNull();
        static::assertInstanceOf(NullType::class, $el);
    }

    #[Test]
    public function encode(): void
    {
        $seq = Sequence::create(NullType::create(), Boolean::create(true));
        $data = $seq->toDER();
        $el = Sequence::fromDER($data);
        static::assertInstanceOf(Sequence::class, $el);
        static::assertEquals($seq, $el);
    }

    #[Test]
    public function atOOB(): void
    {
        $seq = Sequence::create(NullType::create(), Boolean::create(true));
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Structure doesn\'t have an element at index 2');
        $seq->at(2);
    }

    #[Test]
    public function wrappedFail(): void
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('SEQUENCE expected, got primitive NULL');
        $wrap->asSequence();
    }
}
