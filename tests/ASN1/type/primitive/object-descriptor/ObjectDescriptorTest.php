<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\ObjectDescriptor;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * @group type
 * @group object-descriptor
 *
 * @internal
 */
class ObjectDescriptorTest extends TestCase
{
    const DESCRIPTOR = 'test';

    public function testCreate()
    {
        $el = new ObjectDescriptor(self::DESCRIPTOR);
        $this->assertInstanceOf(ObjectDescriptor::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     */
    public function testTag(Element $el)
    {
        $this->assertEquals(Element::TYPE_OBJECT_DESCRIPTOR, $el->tag());
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data): ObjectDescriptor
    {
        $el = ObjectDescriptor::fromDER($data);
        $this->assertInstanceOf(ObjectDescriptor::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Element $ref, Element $el)
    {
        $this->assertEquals($ref, $el);
    }

    /**
     * @depends testCreate
     */
    public function testDescriptor(ObjectDescriptor $desc)
    {
        $this->assertEquals(self::DESCRIPTOR, $desc->descriptor());
    }

    /**
     * @depends testCreate
     */
    public function testWrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(ObjectDescriptor::class,
            $wrap->asObjectDescriptor());
    }

    public function testWrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(
            'ObjectDescriptor expected, got primitive NULL');
        $wrap->asObjectDescriptor();
    }
}
