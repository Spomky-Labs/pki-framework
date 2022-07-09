<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1\Collection;

use PHPUnit\Framework\TestCase;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\Collection\AttributeCollection;
use Sop\X501\ASN1\Collection\SequenceOfAttributes;
use UnexpectedValueException;

/**
 * @internal
 */
final class AttributeCollectionTest extends TestCase
{
    /**
     * @test
     */
    public function create()
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
     * @depends create
     *
     * @test
     */
    public function has(AttributeCollection $c)
    {
        $this->assertTrue($c->has('name'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNot(AttributeCollection $c)
    {
        $this->assertFalse($c->has('commonName'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstOf(AttributeCollection $c)
    {
        $this->assertEquals('n1', $c->firstOf('name')->first()->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstOfFails(AttributeCollection $c)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('No commonName attribute');
        $c->firstOf('commonName');
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOf(AttributeCollection $c)
    {
        $vals = array_map(fn (Attribute $attr) => $attr->first()->stringValue(), $c->allOf('name'));
        $this->assertEquals(['n1', 'n2'], $vals);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOfNone(AttributeCollection $c)
    {
        $this->assertEquals([], $c->allOf('commonName'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(AttributeCollection $c)
    {
        $vals = array_map(fn (Attribute $attr) => $attr->first()->stringValue(), $c->all());
        $this->assertEquals(['n1', 'n2', 'd'], $vals);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withAdditional(AttributeCollection $c)
    {
        $c = $c->withAdditional(Attribute::fromAttributeValues(new CommonNameValue('cn')));
        $vals = array_map(fn (Attribute $attr) => $attr->first()->stringValue(), $c->all());
        $this->assertEquals(['n1', 'n2', 'd', 'cn'], $vals);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withUnique(AttributeCollection $c)
    {
        $c = $c->withUnique(Attribute::fromAttributeValues(new NameValue('uniq')));
        $vals = array_map(fn (Attribute $attr) => $attr->first()->stringValue(), $c->all());
        $this->assertEquals(['d', 'uniq'], $vals);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(AttributeCollection $c)
    {
        $this->assertCount(3, $c);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(AttributeCollection $c)
    {
        $vals = [];
        foreach ($c as $attr) {
            $vals[] = $attr->first()->stringValue();
        }
        $this->assertEquals(['n1', 'n2', 'd'], $vals);
    }
}
