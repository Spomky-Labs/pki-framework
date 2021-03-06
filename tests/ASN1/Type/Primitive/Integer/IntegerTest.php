<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Integer;

use Brick\Math\BigInteger;
use Brick\Math\Exception\IntegerOverflowException;
use const PHP_INT_MAX;
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
    /**
     * @test
     */
    public function create(): Integer
    {
        $el = new Integer(1);
        static::assertInstanceOf(Integer::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_INTEGER, $el->tag());
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
     * @test
     */
    public function decode(string $data): Integer
    {
        $el = Integer::fromDER($data);
        static::assertInstanceOf(Integer::class, $el);
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
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(Integer::class, $wrap->asInteger());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('INTEGER expected, got primitive NULL');
        $wrap->asInteger();
    }

    /**
     * @depends create
     *
     * @param Element $el
     *
     * @test
     */
    public function intNumber(Integer $el)
    {
        static::assertEquals(1, $el->intNumber());
    }

    /**
     * @test
     */
    public function intNumberOverflow()
    {
        $num = BigInteger::of(PHP_INT_MAX)->plus(1);
        $int = new Integer($num);
        $this->expectException(IntegerOverflowException::class);
        $int->intNumber();
    }
}
