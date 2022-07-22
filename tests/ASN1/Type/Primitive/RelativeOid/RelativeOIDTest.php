<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\RelativeOid;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\RelativeOID;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class RelativeOIDTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = new RelativeOID('1.3.6.1.3');
        static::assertInstanceOf(RelativeOID::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_RELATIVE_OID, $el->tag());
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
    public function decode(string $data): RelativeOID
    {
        $el = RelativeOID::fromDER($data);
        static::assertInstanceOf(RelativeOID::class, $el);
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
        static::assertInstanceOf(RelativeOID::class, $wrap->asRelativeOID());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('RELATIVE-OID expected, got primitive NULL');
        $wrap->asRelativeOID();
    }
}
