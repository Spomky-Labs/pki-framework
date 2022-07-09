<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1;

use \LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\AttributeValue\NameValue;

/**
 * @group asn1
 *
 * @internal
 */
class AttributeTest extends TestCase
{
    public function testCreate()
    {
        $attr = Attribute::fromAttributeValues(new NameValue('one'),
            new NameValue('two'));
        $this->assertInstanceOf(Attribute::class, $attr);
        return $attr;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Attribute $attr)
    {
        $der = $attr->toASN1()->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $attr = Attribute::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(Attribute::class, $attr);
        return $attr;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Attribute $ref, Attribute $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testType(Attribute $attr)
    {
        $this->assertEquals(AttributeType::fromName('name'), $attr->type());
    }

    /**
     * @depends testCreate
     */
    public function testFirst(Attribute $attr)
    {
        $this->assertEquals('one', $attr->first()->rfc2253String());
    }

    /**
     * @depends testCreate
     */
    public function testValues(Attribute $attr)
    {
        $this->assertContainsOnlyInstancesOf(AttributeValue::class, $attr->values());
    }

    /**
     * @depends testCreate
     */
    public function testCount(Attribute $attr)
    {
        $this->assertCount(2, $attr);
    }

    /**
     * @depends testCreate
     */
    public function testIterable(Attribute $attr)
    {
        $values = [];
        foreach ($attr as $value) {
            $values[] = $value;
        }
        $this->assertContainsOnlyInstancesOf(AttributeValue::class, $values);
    }

    public function testCreateMismatch()
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Attribute OID mismatch');
        Attribute::fromAttributeValues(new NameValue('name'),
            new CommonNameValue('cn'));
    }

    public function testEmptyFromValuesFail()
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('No values');
        Attribute::fromAttributeValues();
    }

    public function testCreateEmpty()
    {
        $attr = new Attribute(AttributeType::fromName('cn'));
        $this->assertInstanceOf(Attribute::class, $attr);
        return $attr;
    }

    /**
     * @depends testCreateEmpty
     */
    public function testEmptyFirstFail(Attribute $attr)
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Attribute contains no values');
        $attr->first();
    }
}
