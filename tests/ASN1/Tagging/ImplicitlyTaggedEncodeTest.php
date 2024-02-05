<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;

/**
 * @internal
 */
final class ImplicitlyTaggedEncodeTest extends TestCase
{
    #[Test]
    public function null()
    {
        $el = ImplicitlyTaggedType::create(0, NullType::create());
        static::assertSame("\x80\x0", $el->toDER());
    }

    #[Test]
    public function longTag()
    {
        $el = ImplicitlyTaggedType::create(255, NullType::create());
        static::assertSame("\x9f\x81\x7f\x0", $el->toDER());
    }

    #[Test]
    public function recode()
    {
        $el = ImplicitlyTaggedType::create(0, Boolean::create(true));
        static::assertInstanceOf(Boolean::class, $el->implicit(Element::TYPE_BOOLEAN)->asBoolean());
    }
}
