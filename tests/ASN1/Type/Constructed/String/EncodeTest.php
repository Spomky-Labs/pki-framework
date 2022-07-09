<?php

declare(strict_types = 1);

namespace Sop\Test\ASN1\Type\Constructed\String;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\ConstructedString;

/**
 * @group structure
 * @group string
 *
 * @internal
 */
class EncodeTest extends TestCase
{
    public function testEncodeDefinite()
    {
        $el = ConstructedString::createWithTag(Element::TYPE_OCTET_STRING);
        $this->assertEquals(hex2bin('2400'), $el->toDER());
    }

    public function testEncodeIndefinite()
    {
        $el = ConstructedString::createWithTag(Element::TYPE_OCTET_STRING)
            ->withIndefiniteLength();
        $this->assertEquals(hex2bin('24800000'), $el->toDER());
    }
}
