<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\AttributeValue\NameValue;

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
        $this->assertInstanceOf(Attribute::class, $attr);
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
        $this->assertIsString($der);
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
        $this->assertInstanceOf(Attribute::class, $attr);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function type(Attribute $attr)
    {
        $this->assertEquals(AttributeType::fromName('name'), $attr->type());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function first(Attribute $attr)
    {
        $this->assertEquals('one', $attr->first()->rfc2253String());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function values(Attribute $attr)
    {
        $this->assertContainsOnlyInstancesOf(AttributeValue::class, $attr->values());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Attribute $attr)
    {
        $this->assertCount(2, $attr);
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
        $this->assertContainsOnlyInstancesOf(AttributeValue::class, $values);
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
        $this->assertInstanceOf(Attribute::class, $attr);
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
