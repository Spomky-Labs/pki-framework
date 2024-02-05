<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\Sequence;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function encode()
    {
        $el = Sequence::create();
        static::assertSame("\x30\x0", $el->toDER());
    }

    #[Test]
    public function single()
    {
        $el = Sequence::create(NullType::create());
        static::assertSame("\x30\x2\x5\x0", $el->toDER());
    }

    #[Test]
    public function three()
    {
        $el = Sequence::create(NullType::create(), NullType::create(), NullType::create());
        static::assertSame("\x30\x6" . str_repeat("\x5\x0", 3), $el->toDER());
    }

    #[Test]
    public function nested()
    {
        $el = Sequence::create(Sequence::create(NullType::create()));
        static::assertSame("\x30\x4\x30\x2\x5\x0", $el->toDER());
    }
}
