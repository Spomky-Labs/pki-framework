<?php

declare(strict_types=1);

namespace unit\asn1\collection;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Set;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\Collection\SetOfAttributes;

/**
 * @group asn1
 *
 * @internal
 */
class SetOfAttributesTest extends TestCase
{
    public function testCreate()
    {
        $c = SetOfAttributes::fromAttributeValues(
            new NameValue('n'),
            new DescriptionValue('d')
        );
        $this->assertInstanceOf(SetOfAttributes::class, $c);
        return $c;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(SetOfAttributes $c)
    {
        $el = $c->toASN1();
        $this->assertInstanceOf(Set::class, $el);
        return $el;
    }

    /**
     * @depends testEncode
     */
    public function testDecode(Set $set)
    {
        $c = SetOfAttributes::fromASN1($set);
        $this->assertInstanceOf(SetOfAttributes::class, $c);
        return $c;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(SetOfAttributes $original, SetOfAttributes $recoded)
    {
        // compare DER encodings because SET OF sorts the elements
        $this->assertEquals($original->toASN1()->toDER(), $recoded->toASN1()->toDER());
    }
}
