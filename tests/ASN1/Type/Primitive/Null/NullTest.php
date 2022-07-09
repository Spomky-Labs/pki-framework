<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Null;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class NullTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = new NullType();
        $this->assertInstanceOf(NullType::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_NULL, $el->tag());
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
     * @param string $data
     *
     * @test
     */
    public function decode($data): NullType
    {
        $el = NullType::fromDER($data);
        $this->assertInstanceOf(NullType::class, $el);
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
        $this->assertInstanceOf(NullType::class, $wrap->asNull());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new Boolean(true));
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('NULL expected, got primitive BOOLEAN');
        $wrap->asNull();
    }
}
