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
        static::assertInstanceOf(AttributeCollection::class, $c);
        return $c;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function has(AttributeCollection $c)
    {
        static::assertTrue($c->has('name'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNot(AttributeCollection $c)
    {
        static::assertFalse($c->has('commonName'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstOf(AttributeCollection $c)
    {
        static::assertEquals('n1', $c->firstOf('name')->first()->stringValue());
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
        static::assertEquals(['n1', 'n2'], $vals);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOfNone(AttributeCollection $c)
    {
        static::assertEquals([], $c->allOf('commonName'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(AttributeCollection $c)
    {
        $vals = array_map(fn (Attribute $attr) => $attr->first()->stringValue(), $c->all());
        static::assertEquals(['n1', 'n2', 'd'], $vals);
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
        static::assertEquals(['n1', 'n2', 'd', 'cn'], $vals);
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
        static::assertEquals(['d', 'uniq'], $vals);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(AttributeCollection $c)
    {
        static::assertCount(3, $c);
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
        static::assertEquals(['n1', 'n2', 'd'], $vals);
    }
}
