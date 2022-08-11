<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;

/**
 * @internal
 */
final class ExplicitlyTaggedEncodeTest extends TestCase
{
    /**
     * @test
     */
    public function null()
    {
        $el = new ExplicitlyTaggedType(0, NullType::create());
        static::assertEquals("\xa0\x2\x5\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function nested()
    {
        $el = new ExplicitlyTaggedType(1, new ExplicitlyTaggedType(2, NullType::create()));
        static::assertEquals("\xa1\x4\xa2\x2\x5\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function longTag()
    {
        $el = new ExplicitlyTaggedType(255, NullType::create());
        static::assertEquals("\xbf\x81\x7f\x2\x5\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function recode()
    {
        $el = new ExplicitlyTaggedType(0, Boolean::create(true));
        static::assertInstanceOf(Boolean::class, $el->explicit()->asBoolean());
    }
}
