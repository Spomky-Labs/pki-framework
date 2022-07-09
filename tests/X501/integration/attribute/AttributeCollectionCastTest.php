<?php

declare(strict_types=1);

namespace integration\attribute;

use PHPUnit\Framework\TestCase;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeValue\Feature\DirectoryString;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\Collection\SequenceOfAttributes;

/**
 * @group attribute
 *
 * @internal
 */
class AttributeCollectionCastTest extends TestCase
{
    /**
     * Test that AttributeCollection::_castAttributeValues() can be overridden.
     */
    public function testCast()
    {
        $in = SequenceOfAttributes::fromAttributeValues(
            new \AttributeCollectionCastTest_AttrValue('test'),
            new NameValue('name'));
        $asn1 = $in->toASN1();
        $out = \AttributeCollectionCastTest_Collection::fromASN1($asn1);
        $value = $out->firstOf('1.3.6.1.3')->first();
        $this->assertInstanceOf(\AttributeCollectionCastTest_AttrValue::class, $value);
        $this->assertEquals('test', $value->stringValue());
    }
}

class AttributeCollectionCastTest_Collection extends SequenceOfAttributes
{
    protected static function _castAttributeValues(Attribute $attribute): Attribute
    {
        return '1.3.6.1.3' === $attribute->oid() ?
            $attribute->castValues(AttributeCollectionCastTest_AttrValue::class) :
            $attribute;
    }
}

class AttributeCollectionCastTest_AttrValue extends DirectoryString
{
    public function __construct(string $str)
    {
        $this->_oid = '1.3.6.1.3';
        parent::__construct($str, self::UTF8);
    }
}
