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
        $el = new Set();
        static::assertEquals("\x31\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function setSort()
    {
        $set = new Set(
            new ImplicitlyTaggedType(1, new NullType()),
            new ImplicitlyTaggedType(2, new NullType()),
            new ImplicitlyTaggedType(0, new NullType())
        );
        static::assertEquals("\x31\x6\x80\x0\x81\x0\x82\x0", $set->sortedSet()->toDER());
    }

    /**
     * @test
     */
    public function setSortClasses()
    {
        $set = new Set(
            new ExplicitlyTaggedType(5, new NullType()),
            new ImplicitlyTaggedType(6, new NullType()),
            new NullType()
        );
        static::assertEquals("\x31\x8\x05\x0\xa5\x2\x05\x0\x86\x0", $set->sortedSet()->toDER());
    }

    /**
     * @test
     */
    public function setOfSort()
    {
        $set = new Set(new PrintableString('B'), new PrintableString('C'), new PrintableString('A'));
        static::assertEquals("\x31\x9" . "\x13\x01A" . "\x13\x01B" . "\x13\x01C", $set->sortedSetOf()->toDER());
    }
}
