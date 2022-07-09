<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1\Collection;

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
    /**
     * @test
     */
    public function create()
    {
        $c = SequenceOfAttributes::fromAttributeValues(new NameValue('n'), new DescriptionValue('d'));
        static::assertInstanceOf(SequenceOfAttributes::class, $c);
        return $c;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(SequenceOfAttributes $c)
    {
        $el = $c->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(Sequence $seq)
    {
        $c = SequenceOfAttributes::fromASN1($seq);
        static::assertInstanceOf(SequenceOfAttributes::class, $c);
        return $c;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(SequenceOfAttributes $original, SequenceOfAttributes $recoded)
    {
        static::assertEquals($original, $recoded);
    }
}
