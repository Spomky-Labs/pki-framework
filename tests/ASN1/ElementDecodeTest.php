<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use UnexpectedValueException;

/**
 * @internal
 */
final class ElementDecodeTest extends TestCase
{
    #[Test]
    public function abstract()
    {
        $el = Element::fromDER("\x5\x0");
        static::assertInstanceOf(NullType::class, $el);
    }

    #[Test]
    public function concrete()
    {
        $el = NullType::fromDER("\x5\x0");
        static::assertInstanceOf(NullType::class, $el);
    }

    #[Test]
    public function concreteWrongClass()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage(Boolean::class . ' expected, got ' . NullType::class);
        Boolean::fromDER("\x5\x0");
    }

    #[Test]
    public function unimplementedFail()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('not implemented');
        Element::fromDER("\x1f\x7f\x0");
    }

    #[Test]
    public function expectTaggedFail()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Context specific element expected, got UNIVERSAL');
        Element::fromDER("\x5\x0")->expectTagged();
    }
}
