<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1\Collection;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): SequenceOfAttributes
    {
        $c = SequenceOfAttributes::fromAttributeValues(
            NameValue::create('n1'),
            NameValue::create('n2'),
            DescriptionValue::create('d')
        );
        static::assertInstanceOf(AttributeCollection::class, $c);
        return $c;
    }

    #[Test]
    #[Depends('create')]
    public function has(AttributeCollection $c)
    {
        static::assertTrue($c->has('name'));
    }

    #[Test]
    #[Depends('create')]
    public function hasNot(AttributeCollection $c)
    {
        static::assertFalse($c->has('commonName'));
    }

    #[Test]
    #[Depends('create')]
    public function firstOf(AttributeCollection $c)
    {
        static::assertSame('n1', $c->firstOf('name')->first()->stringValue());
    }

    #[Test]
    #[Depends('create')]
    public function firstOfFails(AttributeCollection $c)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('No commonName attribute');
        $c->firstOf('commonName');
    }

    #[Test]
    #[Depends('create')]
    public function allOf(AttributeCollection $c)
    {
        $vals = array_map(fn (Attribute $attr) => $attr->first()->stringValue(), $c->allOf('name'));
        static::assertSame(['n1', 'n2'], $vals);
    }

    #[Test]
    #[Depends('create')]
    public function allOfNone(AttributeCollection $c)
    {
        static::assertSame([], $c->allOf('commonName'));
    }

    #[Test]
    #[Depends('create')]
    public function all(AttributeCollection $c)
    {
        $vals = array_map(fn (Attribute $attr) => $attr->first()->stringValue(), $c->all());
        static::assertSame(['n1', 'n2', 'd'], $vals);
    }

    #[Test]
    #[Depends('create')]
    public function withAdditional(AttributeCollection $c)
    {
        $c = $c->withAdditional(Attribute::fromAttributeValues(CommonNameValue::create('cn')));
        $vals = array_map(fn (Attribute $attr) => $attr->first()->stringValue(), $c->all());
        static::assertSame(['n1', 'n2', 'd', 'cn'], $vals);
    }

    #[Test]
    #[Depends('create')]
    public function withUnique(AttributeCollection $c)
    {
        $c = $c->withUnique(Attribute::fromAttributeValues(NameValue::create('uniq')));
        $vals = array_map(fn (Attribute $attr) => $attr->first()->stringValue(), $c->all());
        static::assertSame(['d', 'uniq'], $vals);
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(AttributeCollection $c)
    {
        static::assertCount(3, $c);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(AttributeCollection $c)
    {
        $vals = [];
        foreach ($c as $attr) {
            $vals[] = $attr->first()->stringValue();
        }
        static::assertSame(['n1', 'n2', 'd'], $vals);
    }
}
