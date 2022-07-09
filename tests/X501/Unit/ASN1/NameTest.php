<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\Name;
use Sop\X501\ASN1\RDN;
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
        $this->assertInstanceOf(Name::class, $name);
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
        $this->assertIsString($der);
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
        $this->assertInstanceOf(Name::class, $name);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(Name $name)
    {
        $this->assertContainsOnlyInstancesOf(RDN::class, $name->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstValueOf(Name $name)
    {
        $this->assertEquals('two', $name->firstValueOf('name')->stringValue());
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
        $this->assertCount(2, $name);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countOfType(Name $name)
    {
        $this->assertEquals(2, $name->countOfType('name'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countOfTypeNone(Name $name)
    {
        $this->assertEquals(0, $name->countOfType('cn'));
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
        $this->assertContainsOnlyInstancesOf(RDN::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(Name $name)
    {
        $this->assertEquals('name=one,name=two', $name->toString());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(Name $name)
    {
        $this->assertIsString(strval($name));
    }
}
