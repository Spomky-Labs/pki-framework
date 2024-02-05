<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\NameValue;

/**
 * @internal
 */
final class AttributeTest extends TestCase
{
    #[Test]
    public function create(): Attribute
    {
        $attr = Attribute::fromAttributeValues(NameValue::create('one'), NameValue::create('two'));
        static::assertInstanceOf(Attribute::class, $attr);
        return $attr;
    }

    #[Test]
    #[Depends('create')]
    public function encode(Attribute $attr): string
    {
        $der = $attr->toASN1()
            ->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): Attribute
    {
        $attr = Attribute::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Attribute::class, $attr);
        return $attr;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Attribute $ref, Attribute $new): void
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function type(Attribute $attr): void
    {
        static::assertEquals(AttributeType::fromName('name'), $attr->type());
    }

    #[Test]
    #[Depends('create')]
    public function first(Attribute $attr): void
    {
        static::assertSame('one', $attr->first()->rfc2253String());
    }

    #[Test]
    #[Depends('create')]
    public function values(Attribute $attr): void
    {
        static::assertContainsOnlyInstancesOf(AttributeValue::class, $attr->values());
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(Attribute $attr): void
    {
        static::assertCount(2, $attr);
    }

    #[Test]
    #[Depends('create')]
    public function iterable(Attribute $attr): void
    {
        $values = [];
        foreach ($attr as $value) {
            $values[] = $value;
        }
        static::assertContainsOnlyInstancesOf(AttributeValue::class, $values);
    }

    #[Test]
    public function createMismatch(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Attribute OID mismatch');
        Attribute::fromAttributeValues(NameValue::create('name'), CommonNameValue::create('cn'));
    }

    #[Test]
    public function emptyFromValuesFail(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('No values');
        Attribute::fromAttributeValues();
    }

    #[Test]
    public function emptyFirstFail(): void
    {
        $attr = Attribute::create(AttributeType::fromName('cn'));
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Attribute contains no values');
        $attr->first();
    }
}
