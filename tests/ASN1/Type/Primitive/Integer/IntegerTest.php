<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Integer;

use const PHP_INT_MAX;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class IntegerTest extends TestCase
{
    /**
     * @test
     */
    public function create()
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
        $wrap = new UnspecifiedType($el);
        static::assertInstanceOf(Integer::class, $wrap->asInteger());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
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
        $num = gmp_init(PHP_INT_MAX, 10) + 1;
        $int = new Integer(gmp_strval($num, 10));
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Integer overflow.');
        $int->intNumber();
    }
}
