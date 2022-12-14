<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\DERData;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;

/**
 * @internal
 */
final class DERDataTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = DERData::create("\x5\x0");
        static::assertEquals(Element::TYPE_NULL, $el->tag());
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function class(DERData $el)
    {
        static::assertEquals(Identifier::CLASS_UNIVERSAL, $el->typeClass());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function constructed(DERData $el)
    {
        static::assertFalse($el->isConstructed());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(DERData $el)
    {
        static::assertEquals("\x5\x0", $el->toDER());
    }

    /**
     * @test
     */
    public function encodeIntoSequence()
    {
        $el = DERData::create("\x5\x0");
        $seq = Sequence::create($el);
        static::assertEquals("\x30\x2\x5\x0", $seq->toDER());
    }

    /**
     * @test
     */
    public function encodeIntoSequenceWithOther()
    {
        $el = DERData::create("\x5\x0");
        $seq = Sequence::create($el, Boolean::create(true));
        static::assertEquals("\x30\x5\x5\x0\x1\x1\xff", $seq->toDER());
    }

    /**
     * @test
     */
    public function encodedContentEmpty()
    {
        $el = DERData::create("\x5\x0");
        $cls = new ReflectionClass($el);
        $mtd = $cls->getMethod('encodedAsDER');
        $mtd->setAccessible(true);
        $content = $mtd->invoke($el);
        static::assertEquals('', $content);
    }

    /**
     * @test
     */
    public function encodedContentValue()
    {
        $el = DERData::create((OctetString::create('test'))->toDER());
        $cls = new ReflectionClass($el);
        $mtd = $cls->getMethod('encodedAsDER');
        $mtd->setAccessible(true);
        $content = $mtd->invoke($el);
        static::assertEquals('test', $content);
    }
}
