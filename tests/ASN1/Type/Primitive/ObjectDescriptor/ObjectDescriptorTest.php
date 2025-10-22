<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\ObjectDescriptor;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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

    #[Test]
    public function create(): ObjectDescriptor
    {
        $el = ObjectDescriptor::create(self::DESCRIPTOR);
        static::assertInstanceOf(ObjectDescriptor::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_OBJECT_DESCRIPTOR, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): ObjectDescriptor
    {
        $el = ObjectDescriptor::fromDER($data);
        static::assertInstanceOf(ObjectDescriptor::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    #[Test]
    #[Depends('create')]
    public function descriptor(ObjectDescriptor $desc)
    {
        static::assertSame(self::DESCRIPTOR, $desc->descriptor());
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(ObjectDescriptor::class, $wrap->asObjectDescriptor());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('ObjectDescriptor expected, got primitive NULL');
        $wrap->asObjectDescriptor();
    }
}
