<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ExplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X501\ASN1\Name;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralName;

/**
 * @internal
 */
final class DirectoryNameTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $name = DirectoryName::fromDNString('cn=Test');
        $this->assertInstanceOf(DirectoryName::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(DirectoryName $name)
    {
        $el = $name->toASN1();
        $this->assertInstanceOf(ExplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function choiceTag($der)
    {
        $el = TaggedType::fromDER($der);
        $this->assertEquals(GeneralName::TAG_DIRECTORY_NAME, $el->tag());
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
        $name = DirectoryName::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(DirectoryName::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(DirectoryName $ref, DirectoryName $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(DirectoryName $name)
    {
        $this->assertEquals('cn=Test', $name->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function dN(DirectoryName $name)
    {
        $this->assertEquals(Name::fromString('cn=Test'), $name->dn());
    }
}
