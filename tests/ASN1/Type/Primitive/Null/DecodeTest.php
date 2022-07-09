<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Null;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\NullType;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    public function testType()
    {
        $el = NullType::fromDER("\x5\0");
        $this->assertInstanceOf(NullType::class, $el);
    }

    public function testInvalidLength()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Expected length 0, got 1');
        NullType::fromDER("\x5\x1\x0");
    }

    public function testNotPrimitive()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Null value must be primitive');
        NullType::fromDER("\x25\x0");
    }
}
