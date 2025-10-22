<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Utf8String;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class UTF8StringTest extends TestCase
{
    #[Test]
    public function create(): UTF8String
    {
        $el = UTF8String::create('');
        static::assertInstanceOf(UTF8String::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_UTF8_STRING, $el->tag());
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
    public function decode($data): UTF8String
    {
        $el = UTF8String::fromDER($data);
        static::assertInstanceOf(UTF8String::class, $el);
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
    public function invalidString()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Not a valid UTF8String string');
        UTF8String::create(hex2bin('ff'));
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(UTF8String::class, $wrap->asUTF8String());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('UTF8String expected, got primitive NULL');
        $wrap->asUTF8String();
    }
}
