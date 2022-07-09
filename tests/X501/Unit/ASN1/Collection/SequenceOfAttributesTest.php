<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1\Collection;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\Collection\SequenceOfAttributes;

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
        $this->assertInstanceOf(SequenceOfAttributes::class, $c);
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
        $this->assertInstanceOf(Sequence::class, $el);
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
        $this->assertInstanceOf(SequenceOfAttributes::class, $c);
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
        $this->assertEquals($original, $recoded);
    }
}
