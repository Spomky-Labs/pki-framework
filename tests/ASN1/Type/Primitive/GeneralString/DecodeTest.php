<?php

declare(strict_types = 1);

namespace Sop\Test\ASN1\Type\Primitive\GeneralString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\GeneralString;

/**
 * @group decode
 * @group general-string
 *
 * @internal
 */
class DecodeTest extends TestCase
{
    public function testType()
    {
        $el = GeneralString::fromDER("\x1b\x0");
        $this->assertInstanceOf(GeneralString::class, $el);
    }

    public function testValue()
    {
        $str = 'Hello World!';
        $el = GeneralString::fromDER("\x1b\x0c{$str}");
        $this->assertEquals($str, $el->string());
    }
}
