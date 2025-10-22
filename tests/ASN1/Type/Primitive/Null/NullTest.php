<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Null;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class NullTest extends TestCase
{
    #[Test]
    public function create(): NullType
    {
        $el = NullType::create();
        static::assertInstanceOf(NullType::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_NULL, $el->tag());
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
    public function decode($data): NullType
    {
        $el = NullType::fromDER($data);
        static::assertInstanceOf(NullType::class, $el);
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
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(NullType::class, $wrap->asNull());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(Boolean::create(true));
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('NULL expected, got primitive BOOLEAN');
        $wrap->asNull();
    }
}
