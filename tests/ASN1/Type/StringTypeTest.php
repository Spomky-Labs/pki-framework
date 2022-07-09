<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\StringType;
use Sop\ASN1\Type\UnspecifiedType;

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
        $this->assertInstanceOf(StringType::class, $wrap->asString());
    }

    /**
     * @test
     */
    public function stringable()
    {
        $s = new OctetString('test');
        $this->assertEquals('test', strval($s));
    }
}
