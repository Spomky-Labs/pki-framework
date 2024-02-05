<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\StringType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use function strval;

/**
 * @internal
 */
final class StringTypeTest extends TestCase
{
    #[Test]
    public function wrapped()
    {
        $wrap = UnspecifiedType::create(OctetString::create(''));
        static::assertInstanceOf(StringType::class, $wrap->asString());
    }

    #[Test]
    public function stringable()
    {
        $s = OctetString::create('test');
        static::assertSame('test', strval($s));
    }
}
