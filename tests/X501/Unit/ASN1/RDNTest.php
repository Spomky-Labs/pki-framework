<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\X501\ASN1\AttributeTypeAndValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\NameValue;
use SpomkyLabs\Pki\X501\ASN1\RDN;
use function strval;
use UnexpectedValueException;

/**
 * @internal
 */
final class RDNTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $rdn = RDN::fromAttributeValues(new NameValue('one'), new NameValue('two'));
        static::assertInstanceOf(RDN::class, $rdn);
        return $rdn;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(RDN $rdn)
    {
        $der = $rdn->toASN1()
            ->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $rdn = RDN::fromASN1(Set::fromDER($der));
        static::assertInstanceOf(RDN::class, $rdn);
        return $rdn;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(RDN $ref, RDN $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(RDN $rdn)
    {
        static::assertContainsOnlyInstancesOf(AttributeTypeAndValue::class, $rdn->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOf(RDN $rdn)
    {
        static::assertContainsOnlyInstancesOf(AttributeTypeAndValue::class, $rdn->allOf('name'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOfCount(RDN $rdn)
    {
        static::assertCount(2, $rdn->allOf('name'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOfEmpty(RDN $rdn)
    {
        static::assertEmpty($rdn->allOf('cn'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(RDN $rdn)
    {
        static::assertCount(2, $rdn);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterable(RDN $rdn)
    {
        $values = [];
        foreach ($rdn as $tv) {
            $values[] = $tv;
        }
        static::assertContainsOnlyInstancesOf(AttributeTypeAndValue::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(RDN $rdn)
    {
        static::assertEquals('name=one+name=two', $rdn->toString());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(RDN $rdn)
    {
        static::assertIsString(strval($rdn));
    }

    /**
     * @test
     */
    public function createFail()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('RDN must have at least one AttributeTypeAndValue');
        new RDN();
    }
}
