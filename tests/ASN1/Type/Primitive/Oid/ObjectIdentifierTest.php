<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Oid;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class ObjectIdentifierTest extends TestCase
{
    #[Test]
    public function create(): ObjectIdentifier
    {
        $el = ObjectIdentifier::create('1.3.6.1.3');
        static::assertInstanceOf(ObjectIdentifier::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_OBJECT_IDENTIFIER, $el->tag());
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
    public function decode(string $data): ObjectIdentifier
    {
        $el = ObjectIdentifier::fromDER($data);
        static::assertInstanceOf(ObjectIdentifier::class, $el);
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
        static::assertInstanceOf(ObjectIdentifier::class, $wrap->asObjectIdentifier());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('OBJECT IDENTIFIER expected, got primitive NULL');
        $wrap->asObjectIdentifier();
    }

    #[Test]
    public function onlyRootArc()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('OID must have at least two nodes');
        ObjectIdentifier::create('0');
    }

    #[Test]
    public function invalidRootArc()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Root arc must be in range of 0..2');
        ObjectIdentifier::create('3.0');
    }

    #[Test]
    public function invalidSubarc()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Second node must be in 0..39 range for root arcs 0 and 1');
        ObjectIdentifier::create('0.40');
    }

    #[Test]
    public function invalidSubarc1()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Second node must be in 0..39 range for root arcs 0 and 1');
        ObjectIdentifier::create('1.40');
    }

    #[Test]
    public function invalidNumber()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('"x" is not a number.');
        ObjectIdentifier::create('1.1.x');
    }

    /**
     * @param string $oid
     */
    #[Test]
    #[DataProvider('oidProvider')]
    public function oID($oid)
    {
        $x = ObjectIdentifier::create($oid);
        $der = $x->toDER();
        static::assertSame($oid, UnspecifiedType::fromDER($der)->asObjectIdentifier()->oid());
    }

    /**
     * @return string[]
     */
    public static function oidProvider()
    {
        return array_map(
            fn ($x) => [$x],
            ['0.0', '0.1', '1.0', '0.0.0', '0.39', '1.39', '2.39', '2.40', '2.999999', '2.99999.1']
        );
    }
}
