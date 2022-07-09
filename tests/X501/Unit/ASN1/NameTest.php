<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\Name;
use Sop\X501\ASN1\RDN;

/**
 * @internal
 */
final class NameTest extends TestCase
{
    public function testCreate()
    {
        $name = Name::fromString('name=one,name=two');
        $this->assertInstanceOf(Name::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Name $name)
    {
        $der = $name->toASN1()
            ->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $name = Name::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(Name::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Name $ref, Name $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testAll(Name $name)
    {
        $this->assertContainsOnlyInstancesOf(RDN::class, $name->all());
    }

    /**
     * @depends testCreate
     */
    public function testFirstValueOf(Name $name)
    {
        $this->assertEquals('two', $name->firstValueOf('name')->stringValue());
    }

    /**
     * @depends testCreate
     */
    public function testFirstValueOfNotFound(Name $name)
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Attribute cn not found');
        $name->firstValueOf('cn');
    }

    public function testFirstValueOfMultipleFail()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('RDN with multiple name attributes');
        Name::fromString('name=one+name=two')->firstValueOf('name');
    }

    /**
     * @depends testCreate
     */
    public function testCount(Name $name)
    {
        $this->assertCount(2, $name);
    }

    /**
     * @depends testCreate
     */
    public function testCountOfType(Name $name)
    {
        $this->assertEquals(2, $name->countOfType('name'));
    }

    /**
     * @depends testCreate
     */
    public function testCountOfTypeNone(Name $name)
    {
        $this->assertEquals(0, $name->countOfType('cn'));
    }

    /**
     * @depends testCreate
     */
    public function testIterable(Name $name)
    {
        $values = [];
        foreach ($name as $rdn) {
            $values[] = $rdn;
        }
        $this->assertContainsOnlyInstancesOf(RDN::class, $values);
    }

    /**
     * @depends testCreate
     */
    public function testString(Name $name)
    {
        $this->assertEquals('name=one,name=two', $name->toString());
    }

    /**
     * @depends testCreate
     */
    public function testToString(Name $name)
    {
        $this->assertIsString(strval($name));
    }
}
