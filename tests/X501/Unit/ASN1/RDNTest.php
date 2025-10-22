<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\X501\ASN1\AttributeTypeAndValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\NameValue;
use SpomkyLabs\Pki\X501\ASN1\RDN;
use UnexpectedValueException;
use function strval;

/**
 * @internal
 */
final class RDNTest extends TestCase
{
    #[Test]
    public function create(): RDN
    {
        $rdn = RDN::fromAttributeValues(NameValue::create('one'), NameValue::create('two'));
        static::assertInstanceOf(RDN::class, $rdn);
        return $rdn;
    }

    #[Test]
    #[Depends('create')]
    public function encode(RDN $rdn): string
    {
        $der = $rdn->toASN1()
            ->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): RDN
    {
        $rdn = RDN::fromASN1(Set::fromDER($der));
        static::assertInstanceOf(RDN::class, $rdn);
        return $rdn;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(RDN $ref, RDN $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function all(RDN $rdn)
    {
        static::assertContainsOnlyInstancesOf(AttributeTypeAndValue::class, $rdn->all());
    }

    #[Test]
    #[Depends('create')]
    public function allOf(RDN $rdn)
    {
        static::assertContainsOnlyInstancesOf(AttributeTypeAndValue::class, $rdn->allOf('name'));
    }

    #[Test]
    #[Depends('create')]
    public function allOfCount(RDN $rdn)
    {
        static::assertCount(2, $rdn->allOf('name'));
    }

    #[Test]
    #[Depends('create')]
    public function allOfEmpty(RDN $rdn)
    {
        static::assertEmpty($rdn->allOf('cn'));
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(RDN $rdn)
    {
        static::assertCount(2, $rdn);
    }

    #[Test]
    #[Depends('create')]
    public function iterable(RDN $rdn)
    {
        $values = [];
        foreach ($rdn as $tv) {
            $values[] = $tv;
        }
        static::assertContainsOnlyInstancesOf(AttributeTypeAndValue::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function string(RDN $rdn)
    {
        static::assertSame('name=one+name=two', $rdn->toString());
    }

    #[Test]
    #[Depends('create')]
    public function toStringMethod(RDN $rdn)
    {
        static::assertIsString(strval($rdn));
    }

    #[Test]
    public function createFail()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('RDN must have at least one AttributeTypeAndValue');
        RDN::create();
    }
}
