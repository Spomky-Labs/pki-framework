<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\Sequence;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;

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
        $el = Sequence::create();
        static::assertEquals("\x30\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function single()
    {
        $el = Sequence::create(new NullType());
        static::assertEquals("\x30\x2\x5\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function three()
    {
        $el = Sequence::create(new NullType(), new NullType(), new NullType());
        static::assertEquals("\x30\x6" . str_repeat("\x5\x0", 3), $el->toDER());
    }

    /**
     * @test
     */
    public function nested()
    {
        $el = Sequence::create(Sequence::create(new NullType()));
        static::assertEquals("\x30\x4\x30\x2\x5\x0", $el->toDER());
    }
}
