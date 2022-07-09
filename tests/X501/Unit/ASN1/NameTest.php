<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X501\ASN1\RDN;
use function strval;

/**
 * @internal
 */
final class NameTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $name = Name::fromString('name=one,name=two');
        static::assertInstanceOf(Name::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Name $name)
    {
        $der = $name->toASN1()
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
        $name = Name::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Name::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Name $ref, Name $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(Name $name)
    {
        static::assertContainsOnlyInstancesOf(RDN::class, $name->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstValueOf(Name $name)
    {
        static::assertEquals('two', $name->firstValueOf('name')->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstValueOfNotFound(Name $name)
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Attribute cn not found');
        $name->firstValueOf('cn');
    }

    /**
     * @test
     */
    public function firstValueOfMultipleFail()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('RDN with multiple name attributes');
        Name::fromString('name=one+name=two')->firstValueOf('name');
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Name $name)
    {
        static::assertCount(2, $name);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countOfType(Name $name)
    {
        static::assertEquals(2, $name->countOfType('name'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countOfTypeNone(Name $name)
    {
        static::assertEquals(0, $name->countOfType('cn'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterable(Name $name)
    {
        $values = [];
        foreach ($name as $rdn) {
            $values[] = $rdn;
        }
        static::assertContainsOnlyInstancesOf(RDN::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(Name $name)
    {
        static::assertEquals('name=one,name=two', $name->toString());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(Name $name)
    {
        static::assertIsString(strval($name));
    }
}
