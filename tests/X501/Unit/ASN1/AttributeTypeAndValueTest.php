<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeTypeAndValue;
use Sop\X501\ASN1\AttributeValue\NameValue;

/**
 * @internal
 */
final class AttributeTypeAndValueTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $atv = AttributeTypeAndValue::fromAttributeValue(new NameValue('one'));
        $this->assertInstanceOf(AttributeTypeAndValue::class, $atv);
        return $atv;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(AttributeTypeAndValue $atv)
    {
        $der = $atv->toASN1()
            ->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $atv = AttributeTypeAndValue::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(AttributeTypeAndValue::class, $atv);
        return $atv;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(AttributeTypeAndValue $ref, AttributeTypeAndValue $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function value(AttributeTypeAndValue $atv)
    {
        $this->assertEquals('one', $atv->value()->rfc2253String());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(AttributeTypeAndValue $atv)
    {
        $this->assertEquals('name=one', $atv->toString());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(AttributeTypeAndValue $atv)
    {
        $this->assertIsString(strval($atv));
    }
}
