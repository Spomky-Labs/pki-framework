<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\Certificate\Extension\DistributionPoint\FullName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @group certificate
 * @group extension
 * @group distribution-point
 *
 * @internal
 */
class FullNameTest extends TestCase
{
    const URI = 'urn:test';

    public function testCreate()
    {
        $name = FullName::fromURI(self::URI);
        $this->assertInstanceOf(FullName::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
     *
     * @param FullName $name
     */
    public function testEncode(FullName $name)
    {
        $el = $name->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $name = FullName::fromTaggedType(TaggedType::fromDER($data));
        $this->assertInstanceOf(FullName::class, $name);
        return $name;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param FullName $ref
     * @param FullName $new
     */
    public function testRecoded(FullName $ref, FullName $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param FullName $name
     */
    public function testNames(FullName $name)
    {
        $names = $name->names();
        $this->assertInstanceOf(GeneralNames::class, $names);
    }
}
