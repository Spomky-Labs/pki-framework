<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1\Collection;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\DescriptionValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\NameValue;
use SpomkyLabs\Pki\X501\ASN1\Collection\AttributeCollection;
use SpomkyLabs\Pki\X501\ASN1\Collection\SequenceOfAttributes;
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
            NameValue::create('n1'),
            NameValue::create('n2'),
            DescriptionValue::create('d')
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
        $c = $c->withAdditional(Attribute::fromAttributeValues(CommonNameValue::create('cn')));
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
        $c = $c->withUnique(Attribute::fromAttributeValues(NameValue::create('uniq')));
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
