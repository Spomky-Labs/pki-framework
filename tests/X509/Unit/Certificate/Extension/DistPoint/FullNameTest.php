<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\Certificate\Extension\DistributionPoint\FullName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class FullNameTest extends TestCase
{
    public const URI = 'urn:test';

    /**
     * @test
     */
    public function create()
    {
        $name = FullName::fromURI(self::URI);
        $this->assertInstanceOf(FullName::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(FullName $name)
    {
        $el = $name->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $name = FullName::fromTaggedType(TaggedType::fromDER($data));
        $this->assertInstanceOf(FullName::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(FullName $ref, FullName $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function names(FullName $name)
    {
        $names = $name->names();
        $this->assertInstanceOf(GeneralNames::class, $names);
    }
}
