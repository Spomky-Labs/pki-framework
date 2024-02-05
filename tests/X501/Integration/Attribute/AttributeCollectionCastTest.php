<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Integration\Attribute;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\NameValue;
use SpomkyLabs\Pki\X501\ASN1\Collection\SequenceOfAttributes;

/**
 * @internal
 */
final class AttributeCollectionCastTest extends TestCase
{
    /**
     * Test that AttributeCollection::_castAttributeValues() can be overridden.
     */
    #[Test]
    public function cast()
    {
        $in = SequenceOfAttributes::fromAttributeValues(
            AttributeCollectionCastTestAttrValue::create('test'),
            NameValue::create('name')
        );
        $asn1 = $in->toASN1();
        $out = AttributeCollectionCastTestCollection::fromASN1($asn1);
        $value = $out->firstOf('1.3.6.1.3')
            ->first();
        static::assertInstanceOf(AttributeCollectionCastTestAttrValue::class, $value);
        static::assertSame('test', $value->stringValue());
    }
}
