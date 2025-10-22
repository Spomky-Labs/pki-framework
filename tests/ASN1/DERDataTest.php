<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): DERData
    {
        $el = DERData::create("\x5\x0");
        static::assertSame(Element::TYPE_NULL, $el->tag());
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function class(DERData $el)
    {
        static::assertSame(Identifier::CLASS_UNIVERSAL, $el->typeClass());
    }

    #[Test]
    #[Depends('create')]
    public function constructed(DERData $el)
    {
        static::assertFalse($el->isConstructed());
    }

    #[Test]
    #[Depends('create')]
    public function encode(DERData $el)
    {
        static::assertSame("\x5\x0", $el->toDER());
    }

    #[Test]
    public function encodeIntoSequence()
    {
        $el = DERData::create("\x5\x0");
        $seq = Sequence::create($el);
        static::assertSame("\x30\x2\x5\x0", $seq->toDER());
    }

    #[Test]
    public function encodeIntoSequenceWithOther()
    {
        $el = DERData::create("\x5\x0");
        $seq = Sequence::create($el, Boolean::create(true));
        static::assertSame("\x30\x5\x5\x0\x1\x1\xff", $seq->toDER());
    }

    #[Test]
    public function encodedContentEmpty()
    {
        $el = DERData::create("\x5\x0");
        $cls = new ReflectionClass($el);
        $mtd = $cls->getMethod('encodedAsDER');
        $content = $mtd->invoke($el);
        static::assertSame('', $content);
    }

    #[Test]
    public function encodedContentValue()
    {
        $el = DERData::create((OctetString::create('test'))->toDER());
        $cls = new ReflectionClass($el);
        $mtd = $cls->getMethod('encodedAsDER');
        $content = $mtd->invoke($el);
        static::assertSame('test', $content);
    }
}
