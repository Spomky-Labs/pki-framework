<?php

declare(strict_types=1);

namespace unit\asn1\collection;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\Collection\SequenceOfAttributes;

/**
 * @group asn1
 *
 * @internal
 */
class SequenceOfAttributesTest extends TestCase
{
    public function testCreate()
    {
        $c = SequenceOfAttributes::fromAttributeValues(
            new NameValue('n'),
            new DescriptionValue('d')
        );
        $this->assertInstanceOf(SequenceOfAttributes::class, $c);
        return $c;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(SequenceOfAttributes $c)
    {
        $el = $c->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el;
    }

    /**
     * @depends testEncode
     */
    public function testDecode(Sequence $seq)
    {
        $c = SequenceOfAttributes::fromASN1($seq);
        $this->assertInstanceOf(SequenceOfAttributes::class, $c);
        return $c;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(SequenceOfAttributes $original, SequenceOfAttributes $recoded)
    {
        $this->assertEquals($original, $recoded);
    }
}
