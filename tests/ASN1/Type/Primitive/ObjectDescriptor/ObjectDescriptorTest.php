<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\ObjectDescriptor;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectDescriptor;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class ObjectDescriptorTest extends TestCase
{
    final public const DESCRIPTOR = 'test';

    /**
     * @test
     */
    public function create()
    {
        $el = ObjectDescriptor::create(self::DESCRIPTOR);
        static::assertInstanceOf(ObjectDescriptor::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_OBJECT_DESCRIPTOR, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data): ObjectDescriptor
    {
        $el = ObjectDescriptor::fromDER($data);
        static::assertInstanceOf(ObjectDescriptor::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function descriptor(ObjectDescriptor $desc)
    {
        static::assertEquals(self::DESCRIPTOR, $desc->descriptor());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(ObjectDescriptor::class, $wrap->asObjectDescriptor());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('ObjectDescriptor expected, got primitive NULL');
        $wrap->asObjectDescriptor();
    }
}
