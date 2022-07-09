<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\RelativeOid;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\RelativeOID;
use Sop\ASN1\Type\UnspecifiedType;
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
        $this->assertInstanceOf(RelativeOID::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_RELATIVE_OID, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
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
        $this->assertInstanceOf(RelativeOID::class, $el);
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
        $this->assertEquals($ref, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(RelativeOID::class, $wrap->asRelativeOID());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('RELATIVE-OID expected, got primitive NULL');
        $wrap->asRelativeOID();
    }
}
