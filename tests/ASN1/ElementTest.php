<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * @internal
 */
final class ElementTest extends TestCase
{
    #[Test]
    public function unknownTagToName(): void
    {
        static::assertSame('TAG 100', Element::tagToName(100));
    }

    #[Test]
    public function isPseudotypeFail(): void
    {
        $el = NullType::create();
        static::assertFalse($el->isType(-99));
    }

    #[Test]
    public function asElement(): NullType
    {
        $el = NullType::create();
        static::assertEquals($el, $el->asElement());
        return $el;
    }

    #[Test]
    #[Depends('asElement')]
    public function asUnspecified(Element $el): void
    {
        $type = $el->asUnspecified();
        static::assertInstanceOf(UnspecifiedType::class, $type);
    }

    #[Test]
    public function isIndefinite(): void
    {
        $el = Element::fromDER(hex2bin('308005000000'))->asElement();
        static::assertTrue($el->hasIndefiniteLength());
    }

    #[Test]
    public function setDefinite(): void
    {
        $el = Element::fromDER(hex2bin('308005000000'))->asElement();
        $el = $el->withIndefiniteLength(false);
        static::assertEquals(hex2bin('30020500'), $el->toDER());
    }
}
