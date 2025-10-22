<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1\Collection;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\DescriptionValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\NameValue;
use SpomkyLabs\Pki\X501\ASN1\Collection\SequenceOfAttributes;

/**
 * @internal
 */
final class SequenceOfAttributesTest extends TestCase
{
    #[Test]
    public function create(): SequenceOfAttributes
    {
        $c = SequenceOfAttributes::fromAttributeValues(NameValue::create('n'), DescriptionValue::create('d'));
        static::assertInstanceOf(SequenceOfAttributes::class, $c);
        return $c;
    }

    #[Test]
    #[Depends('create')]
    public function encode(SequenceOfAttributes $c): Sequence
    {
        $el = $c->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): SequenceOfAttributes
    {
        $c = SequenceOfAttributes::fromASN1($seq);
        static::assertInstanceOf(SequenceOfAttributes::class, $c);
        return $c;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(SequenceOfAttributes $original, SequenceOfAttributes $recoded)
    {
        static::assertEquals($original, $recoded);
    }
}
