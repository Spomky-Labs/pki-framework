<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): AttributeTypeAndValue
    {
        $atv = AttributeTypeAndValue::fromAttributeValue(NameValue::create('one'));
        static::assertInstanceOf(AttributeTypeAndValue::class, $atv);
        return $atv;
    }

    #[Test]
    #[Depends('create')]
    public function encode(AttributeTypeAndValue $atv): string
    {
        $der = $atv->toASN1()
            ->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): AttributeTypeAndValue
    {
        $atv = AttributeTypeAndValue::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AttributeTypeAndValue::class, $atv);
        return $atv;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(AttributeTypeAndValue $ref, AttributeTypeAndValue $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function value(AttributeTypeAndValue $atv)
    {
        static::assertSame('one', $atv->value()->rfc2253String());
    }

    #[Test]
    #[Depends('create')]
    public function string(AttributeTypeAndValue $atv)
    {
        static::assertSame('name=one', $atv->toString());
    }

    #[Test]
    #[Depends('create')]
    public function toStringMethod(AttributeTypeAndValue $atv)
    {
        static::assertIsString(strval($atv));
    }
}
