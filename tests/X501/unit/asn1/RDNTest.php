<?php

declare(strict_types=1);

namespace unit\asn1;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Set;
use Sop\X501\ASN1\AttributeTypeAndValue;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\RDN;

/**
 * @group asn1
 *
 * @internal
 */
class RDNTest extends TestCase
{
    public function testCreate()
    {
        $rdn = RDN::fromAttributeValues(new NameValue('one'),
            new NameValue('two'));
        $this->assertInstanceOf(RDN::class, $rdn);
        return $rdn;
    }

    /**
     * @depends testCreate
     *
     * @param RDN $rdn
     */
    public function testEncode(RDN $rdn)
    {
        $der = $rdn->toASN1()->toDER();
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
        $rdn = RDN::fromASN1(Set::fromDER($der));
        $this->assertInstanceOf(RDN::class, $rdn);
        return $rdn;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param RDN $ref
     * @param RDN $new
     */
    public function testRecoded(RDN $ref, RDN $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param RDN $rdn
     */
    public function testAll(RDN $rdn)
    {
        $this->assertContainsOnlyInstancesOf(AttributeTypeAndValue::class,
            $rdn->all());
    }

    /**
     * @depends testCreate
     *
     * @param RDN $rdn
     */
    public function testAllOf(RDN $rdn)
    {
        $this->assertContainsOnlyInstancesOf(AttributeTypeAndValue::class,
            $rdn->allOf('name'));
    }

    /**
     * @depends testCreate
     *
     * @param RDN $rdn
     */
    public function testAllOfCount(RDN $rdn)
    {
        $this->assertCount(2, $rdn->allOf('name'));
    }

    /**
     * @depends testCreate
     *
     * @param RDN $rdn
     */
    public function testAllOfEmpty(RDN $rdn)
    {
        $this->assertEmpty($rdn->allOf('cn'));
    }

    /**
     * @depends testCreate
     *
     * @param RDN $rdn
     */
    public function testCount(RDN $rdn)
    {
        $this->assertCount(2, $rdn);
    }

    /**
     * @depends testCreate
     *
     * @param RDN $rdn
     */
    public function testIterable(RDN $rdn)
    {
        $values = [];
        foreach ($rdn as $tv) {
            $values[] = $tv;
        }
        $this->assertContainsOnlyInstancesOf(AttributeTypeAndValue::class,
            $values);
    }

    /**
     * @depends testCreate
     *
     * @param RDN $rdn
     */
    public function testString(RDN $rdn)
    {
        $this->assertEquals('name=one+name=two', $rdn->toString());
    }

    /**
     * @depends testCreate
     *
     * @param RDN $rdn
     */
    public function testToString(RDN $rdn)
    {
        $this->assertIsString(strval($rdn));
    }

    public function testCreateFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(
            'RDN must have at least one AttributeTypeAndValue');
        new RDN();
    }
}
