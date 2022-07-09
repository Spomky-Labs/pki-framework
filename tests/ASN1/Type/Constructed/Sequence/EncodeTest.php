<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Constructed\Sequence;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\NullType;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    /**
     * @test
     */
    public function encode()
    {
        $el = new Sequence();
        static::assertEquals("\x30\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function single()
    {
        $el = new Sequence(new NullType());
        static::assertEquals("\x30\x2\x5\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function three()
    {
        $el = new Sequence(new NullType(), new NullType(), new NullType());
        static::assertEquals("\x30\x6" . str_repeat("\x5\x0", 3), $el->toDER());
    }

    /**
     * @test
     */
    public function nested()
    {
        $el = new Sequence(new Sequence(new NullType()));
        static::assertEquals("\x30\x4\x30\x2\x5\x0", $el->toDER());
    }
}
