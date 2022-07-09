<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type;

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
    /**
     * @test
     */
    public function wrapped()
    {
        $wrap = new UnspecifiedType(new OctetString(''));
        static::assertInstanceOf(StringType::class, $wrap->asString());
    }

    /**
     * @test
     */
    public function stringable()
    {
        $s = new OctetString('test');
        static::assertEquals('test', strval($s));
    }
}
