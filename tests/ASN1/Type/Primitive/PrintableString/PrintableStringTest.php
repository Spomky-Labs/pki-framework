<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\PrintableString;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\PrintableString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class PrintableStringTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = new PrintableString('');
        static::assertInstanceOf(PrintableString::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_PRINTABLE_STRING, $el->tag());
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
    public function decode(string $data): PrintableString
    {
        $el = PrintableString::fromDER($data);
        static::assertInstanceOf(PrintableString::class, $el);
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
        static::assertInstanceOf(PrintableString::class, $wrap->asPrintableString());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('PrintableString expected, got primitive NULL');
        $wrap->asPrintableString();
    }
}
