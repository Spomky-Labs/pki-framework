<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Integer;

use Brick\Math\BigInteger;
use Brick\Math\Exception\IntegerOverflowException;
use const PHP_INT_MAX;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class IntegerTest extends TestCase
{
    #[Test]
    public function create(): Integer
    {
        $el = Integer::create(1);
        static::assertInstanceOf(Integer::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_INTEGER, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $data): Integer
    {
        $el = Integer::fromDER($data);
        static::assertInstanceOf(Integer::class, $el);
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
        static::assertInstanceOf(Integer::class, $wrap->asInteger());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('INTEGER expected, got primitive NULL');
        $wrap->asInteger();
    }

    /**
     * @param Element $el
     */
    #[Test]
    #[Depends('create')]
    public function intNumber(Integer $el)
    {
        static::assertEquals(1, $el->intNumber());
    }

    #[Test]
    public function intNumberOverflow()
    {
        $num = BigInteger::of(PHP_INT_MAX)->plus(1);
        $int = Integer::create($num);
        $this->expectException(IntegerOverflowException::class);
        $int->intNumber();
    }
}
