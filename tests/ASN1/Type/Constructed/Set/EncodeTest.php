<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\Set;

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
    /**
     * @test
     */
    public function encode()
    {
        $el = Set::create();
        static::assertEquals("\x31\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function setSort()
    {
        $set = Set::create(
            new ImplicitlyTaggedType(1, NullType::create()),
            new ImplicitlyTaggedType(2, NullType::create()),
            new ImplicitlyTaggedType(0, NullType::create())
        );
        static::assertEquals("\x31\x6\x80\x0\x81\x0\x82\x0", $set->sortedSet()->toDER());
    }

    /**
     * @test
     */
    public function setSortClasses()
    {
        $set = Set::create(
            new ExplicitlyTaggedType(5, NullType::create()),
            new ImplicitlyTaggedType(6, NullType::create()),
            NullType::create()
        );
        static::assertEquals("\x31\x8\x05\x0\xa5\x2\x05\x0\x86\x0", $set->sortedSet()->toDER());
    }

    /**
     * @test
     */
    public function setOfSort()
    {
        $set = Set::create(PrintableString::create('B'), PrintableString::create('C'), PrintableString::create('A'));
        static::assertEquals("\x31\x9" . "\x13\x01A" . "\x13\x01B" . "\x13\x01C", $set->sortedSetOf()->toDER());
    }
}
