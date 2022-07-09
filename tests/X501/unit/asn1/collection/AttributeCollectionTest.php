<?php

declare(strict_types=1);

namespace unit\asn1\collection;

use PHPUnit\Framework\TestCase;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\Collection\AttributeCollection;
use Sop\X501\ASN1\Collection\SequenceOfAttributes;

/**
 * @group asn1
 *
 * @internal
 */
class AttributeCollectionTest extends TestCase
{
    public function testCreate()
    {
        $c = SequenceOfAttributes::fromAttributeValues(
            new NameValue('n1'),
            new NameValue('n2'),
            new DescriptionValue('d')
        );
        $this->assertInstanceOf(AttributeCollection::class, $c);
        return $c;
    }

    /**
     * @depends testCreate
     */
    public function testHas(AttributeCollection $c)
    {
        $this->assertTrue($c->has('name'));
    }

    /**
     * @depends testCreate
     */
    public function testHasNot(AttributeCollection $c)
    {
        $this->assertFalse($c->has('commonName'));
    }

    /**
     * @depends testCreate
     */
    public function testFirstOf(AttributeCollection $c)
    {
        $this->assertEquals('n1', $c->firstOf('name')->first()->stringValue());
    }

    /**
     * @depends testCreate
     */
    public function testFirstOfFails(AttributeCollection $c)
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('No commonName attribute');
        $c->firstOf('commonName');
    }

    /**
     * @depends testCreate
     */
    public function testAllOf(AttributeCollection $c)
    {
        $vals = array_map(function (Attribute $attr) {
            return $attr->first()->stringValue();
        }, $c->allOf('name'));
        $this->assertEquals(['n1', 'n2'], $vals);
    }

    /**
     * @depends testCreate
     */
    public function testAllOfNone(AttributeCollection $c)
    {
        $this->assertEquals([], $c->allOf('commonName'));
    }

    /**
     * @depends testCreate
     */
    public function testAll(AttributeCollection $c)
    {
        $vals = array_map(function (Attribute $attr) {
            return $attr->first()->stringValue();
        }, $c->all());
        $this->assertEquals(['n1', 'n2', 'd'], $vals);
    }

    /**
     * @depends testCreate
     */
    public function testWithAdditional(AttributeCollection $c)
    {
        $c = $c->withAdditional(
            Attribute::fromAttributeValues(new CommonNameValue('cn'))
        );
        $vals = array_map(function (Attribute $attr) {
            return $attr->first()->stringValue();
        }, $c->all());
        $this->assertEquals(['n1', 'n2', 'd', 'cn'], $vals);
    }

    /**
     * @depends testCreate
     */
    public function testWithUnique(AttributeCollection $c)
    {
        $c = $c->withUnique(
            Attribute::fromAttributeValues(new NameValue('uniq'))
        );
        $vals = array_map(function (Attribute $attr) {
            return $attr->first()->stringValue();
        }, $c->all());
        $this->assertEquals(['d', 'uniq'], $vals);
    }

    /**
     * @depends testCreate
     */
    public function testCount(AttributeCollection $c)
    {
        $this->assertEquals(3, count($c));
    }

    /**
     * @depends testCreate
     */
    public function testIterator(AttributeCollection $c)
    {
        $vals = [];
        foreach ($c as $attr) {
            $vals[] = $attr->first()->stringValue();
        }
        $this->assertEquals(['n1', 'n2', 'd'], $vals);
    }
}
