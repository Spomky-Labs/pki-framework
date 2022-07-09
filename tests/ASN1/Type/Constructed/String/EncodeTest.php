<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\String;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\ConstructedString;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    /**
     * @test
     */
    public function encodeDefinite()
    {
        $el = ConstructedString::createWithTag(Element::TYPE_OCTET_STRING);
        static::assertEquals(hex2bin('2400'), $el->toDER());
    }

    /**
     * @test
     */
    public function encodeIndefinite()
    {
        $el = ConstructedString::createWithTag(Element::TYPE_OCTET_STRING)
            ->withIndefiniteLength();
        static::assertEquals(hex2bin('24800000'), $el->toDER());
    }
}
