<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use LogicException;
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
    /**
     * @test
     */
    public function create()
    {
        $attr = Attribute::fromAttributeValues(new NameValue('one'), new NameValue('two'));
        static::assertInstanceOf(Attribute::class, $attr);
        return $attr;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Attribute $attr)
    {
        $der = $attr->toASN1()
            ->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $attr = Attribute::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Attribute::class, $attr);
        return $attr;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Attribute $ref, Attribute $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function type(Attribute $attr)
    {
        static::assertEquals(AttributeType::fromName('name'), $attr->type());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function first(Attribute $attr)
    {
        static::assertEquals('one', $attr->first()->rfc2253String());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function values(Attribute $attr)
    {
        static::assertContainsOnlyInstancesOf(AttributeValue::class, $attr->values());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Attribute $attr)
    {
        static::assertCount(2, $attr);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterable(Attribute $attr)
    {
        $values = [];
        foreach ($attr as $value) {
            $values[] = $value;
        }
        static::assertContainsOnlyInstancesOf(AttributeValue::class, $values);
    }

    /**
     * @test
     */
    public function createMismatch()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Attribute OID mismatch');
        Attribute::fromAttributeValues(new NameValue('name'), new CommonNameValue('cn'));
    }

    /**
     * @test
     */
    public function emptyFromValuesFail()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('No values');
        Attribute::fromAttributeValues();
    }

    /**
     * @test
     */
    public function createEmpty()
    {
        $attr = new Attribute(AttributeType::fromName('cn'));
        static::assertInstanceOf(Attribute::class, $attr);
        return $attr;
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function emptyFirstFail(Attribute $attr)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Attribute contains no values');
        $attr->first();
    }
}
