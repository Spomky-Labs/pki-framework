<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\Set;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\PrintableString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function encode()
    {
        $el = Set::create();
        static::assertSame("\x31\x0", $el->toDER());
    }

    #[Test]
    public function setSort()
    {
        $set = Set::create(
            ImplicitlyTaggedType::create(1, NullType::create()),
            ImplicitlyTaggedType::create(2, NullType::create()),
            ImplicitlyTaggedType::create(0, NullType::create())
        );
        static::assertSame("\x31\x6\x80\x0\x81\x0\x82\x0", $set->sortedSet()->toDER());
    }

    #[Test]
    public function setSortClasses()
    {
        $set = Set::create(
            ExplicitlyTaggedType::create(5, NullType::create()),
            ImplicitlyTaggedType::create(6, NullType::create()),
            NullType::create()
        );
        static::assertSame("\x31\x8\x05\x0\xa5\x2\x05\x0\x86\x0", $set->sortedSet()->toDER());
    }

    #[Test]
    public function setOfSort()
    {
        $set = Set::create(PrintableString::create('B'), PrintableString::create('C'), PrintableString::create('A'));
        static::assertSame("\x31\x9" . "\x13\x01A" . "\x13\x01B" . "\x13\x01C", $set->sortedSetOf()->toDER());
    }
}
