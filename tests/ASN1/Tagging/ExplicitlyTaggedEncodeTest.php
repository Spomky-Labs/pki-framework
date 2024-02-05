<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;

/**
 * @internal
 */
final class ExplicitlyTaggedEncodeTest extends TestCase
{
    #[Test]
    public function null()
    {
        $el = ExplicitlyTaggedType::create(0, NullType::create());
        static::assertSame("\xa0\x2\x5\x0", $el->toDER());
    }

    #[Test]
    public function nested()
    {
        $el = ExplicitlyTaggedType::create(1, ExplicitlyTaggedType::create(2, NullType::create()));
        static::assertSame("\xa1\x4\xa2\x2\x5\x0", $el->toDER());
    }

    #[Test]
    public function longTag()
    {
        $el = ExplicitlyTaggedType::create(255, NullType::create());
        static::assertSame("\xbf\x81\x7f\x2\x5\x0", $el->toDER());
    }

    #[Test]
    public function recode()
    {
        $el = ExplicitlyTaggedType::create(0, Boolean::create(true));
        static::assertInstanceOf(Boolean::class, $el->explicit()->asBoolean());
    }
}
