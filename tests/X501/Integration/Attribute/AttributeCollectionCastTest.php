<?php

declare(strict_types=1);

namespace Sop\Test\X501\Integration\Attribute;

use PHPUnit\Framework\TestCase;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\Collection\SequenceOfAttributes;

/**
 * @internal
 */
final class AttributeCollectionCastTest extends TestCase
{
    /**
     * Test that AttributeCollection::_castAttributeValues() can be overridden.
     */
    public function testCast()
    {
        $in = SequenceOfAttributes::fromAttributeValues(
            new AttributeCollectionCastTestAttrValue('test'),
            new NameValue('name')
        );
        $asn1 = $in->toASN1();
        $out = AttributeCollectionCastTestCollection::fromASN1($asn1);
        $value = $out->firstOf('1.3.6.1.3')
            ->first();
        $this->assertInstanceOf(AttributeCollectionCastTestAttrValue::class, $value);
        $this->assertEquals('test', $value->stringValue());
    }
}
