<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\RelativeOid;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\RelativeOID;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class RelativeOIDTest extends TestCase
{
    #[Test]
    public function create(): RelativeOID
    {
        $el = RelativeOID::create('1.3.6.1.3');
        static::assertInstanceOf(RelativeOID::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_RELATIVE_OID, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $data): RelativeOID
    {
        $el = RelativeOID::fromDER($data);
        static::assertInstanceOf(RelativeOID::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(RelativeOID::class, $wrap->asRelativeOID());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('RELATIVE-OID expected, got primitive NULL');
        $wrap->asRelativeOID();
    }
}
