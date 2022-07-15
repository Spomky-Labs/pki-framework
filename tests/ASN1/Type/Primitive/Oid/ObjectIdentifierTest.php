<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Oid;

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
    /**
     * @test
     */
    public function create()
    {
        $el = new ObjectIdentifier('1.3.6.1.3');
        static::assertInstanceOf(ObjectIdentifier::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_OBJECT_IDENTIFIER, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(string $data): ObjectIdentifier
    {
        $el = ObjectIdentifier::fromDER($data);
        static::assertInstanceOf(ObjectIdentifier::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        static::assertInstanceOf(ObjectIdentifier::class, $wrap->asObjectIdentifier());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('OBJECT IDENTIFIER expected, got primitive NULL');
        $wrap->asObjectIdentifier();
    }

    /**
     * @test
     */
    public function onlyRootArc()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('OID must have at least two nodes');
        new ObjectIdentifier('0');
    }

    /**
     * @test
     */
    public function invalidRootArc()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Root arc must be in range of 0..2');
        new ObjectIdentifier('3.0');
    }

    /**
     * @test
     */
    public function invalidSubarc()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Second node must be in 0..39 range for root arcs 0 and 1');
        new ObjectIdentifier('0.40');
    }

    /**
     * @test
     */
    public function invalidSubarc1()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Second node must be in 0..39 range for root arcs 0 and 1');
        new ObjectIdentifier('1.40');
    }

    /**
     * @test
     */
    public function invalidNumber()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('"x" is not a number.');
        new ObjectIdentifier('1.1.x');
    }

    /**
     * @dataProvider oidProvider
     *
     * @param string $oid
     *
     * @test
     */
    public function oID($oid)
    {
        $x = new ObjectIdentifier($oid);
        $der = $x->toDER();
        static::assertEquals($oid, UnspecifiedType::fromDER($der)->asObjectIdentifier() ->oid());
    }

    /**
     * @return string[]
     */
    public function oidProvider()
    {
        return array_map(
            fn ($x) => [$x],
            ['0.0', '0.1', '1.0', '0.0.0', '0.39', '1.39', '2.39', '2.40', '2.999999', '2.99999.1']
        );
    }
}
