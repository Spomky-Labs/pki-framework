<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * @internal
 */
final class ElementTest extends TestCase
{
    /**
     * @test
     */
    public function unknownTagToName(): void
    {
        static::assertEquals('TAG 100', Element::tagToName(100));
    }

    /**
     * @test
     */
    public function isPseudotypeFail(): void
    {
        $el = NullType::create();
        static::assertFalse($el->isType(-99));
    }

    /**
     * @test
     */
    public function asElement(): NullType
    {
        $el = NullType::create();
        static::assertEquals($el, $el->asElement());
        return $el;
    }

    /**
     * @depends asElement
     *
     * @test
     */
    public function asUnspecified(Element $el): void
    {
        $type = $el->asUnspecified();
        static::assertInstanceOf(UnspecifiedType::class, $type);
    }

    /**
     * @test
     */
    public function isIndefinite(): void
    {
        $el = Element::fromDER(hex2bin('308005000000'))->asElement();
        static::assertTrue($el->hasIndefiniteLength());
    }

    /**
     * @test
     */
    public function setDefinite(): void
    {
        $el = Element::fromDER(hex2bin('308005000000'))->asElement();
        $el = $el->withIndefiniteLength(false);
        static::assertEquals(hex2bin('30020500'), $el->toDER());
    }
}
