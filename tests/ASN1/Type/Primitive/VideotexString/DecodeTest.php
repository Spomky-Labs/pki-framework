<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\VideotexString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\VideotexString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @test
     */
    public function type()
    {
        $el = VideotexString::fromDER("\x15\x0");
        $this->assertInstanceOf(VideotexString::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $str = 'Hello World!';
        $el = VideotexString::fromDER("\x15\x0c{$str}");
        $this->assertEquals($str, $el->string());
    }
}
