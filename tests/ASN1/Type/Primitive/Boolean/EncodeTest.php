<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Boolean;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    /**
     * @test
     */
    public function true()
    {
        $el = new Boolean(true);
        static::assertEquals("\x1\x1\xff", $el->toDER());
    }

    /**
     * @test
     */
    public function false()
    {
        $el = new Boolean(false);
        static::assertEquals("\x1\x1\x00", $el->toDER());
    }
}
