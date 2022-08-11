<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

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
    /**
     * @test
     */
    public function null()
    {
        $el = new ImplicitlyTaggedType(0, NullType::create());
        static::assertEquals("\x80\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function longTag()
    {
        $el = new ImplicitlyTaggedType(255, NullType::create());
        static::assertEquals("\x9f\x81\x7f\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function recode()
    {
        $el = new ImplicitlyTaggedType(0, Boolean::create(true));
        static::assertInstanceOf(Boolean::class, $el->implicit(Element::TYPE_BOOLEAN)->asBoolean());
    }
}
