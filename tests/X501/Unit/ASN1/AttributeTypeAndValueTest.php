<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\AttributeTypeAndValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\NameValue;
use function strval;

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
        $atv = AttributeTypeAndValue::fromAttributeValue(NameValue::create('one'));
        static::assertInstanceOf(AttributeTypeAndValue::class, $atv);
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
        static::assertIsString($der);
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
        static::assertInstanceOf(AttributeTypeAndValue::class, $atv);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function value(AttributeTypeAndValue $atv)
    {
        static::assertEquals('one', $atv->value()->rfc2253String());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(AttributeTypeAndValue $atv)
    {
        static::assertEquals('name=one', $atv->toString());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(AttributeTypeAndValue $atv)
    {
        static::assertIsString(strval($atv));
    }
}
