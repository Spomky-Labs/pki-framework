<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use LogicException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class GeneralNamesTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $gns = new GeneralNames(new DNSName('test1'), new DNSName('test2'));
        $this->assertInstanceOf(GeneralNames::class, $gns);
        return $gns;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(GeneralNames $gns)
    {
        $seq = $gns->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
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
        $gns = GeneralNames::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(GeneralNames::class, $gns);
        return $gns;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(GeneralNames $ref, GeneralNames $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function has(GeneralNames $gns)
    {
        $this->assertTrue($gns->has(GeneralName::TAG_DNS_NAME));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNot(GeneralNames $gns)
    {
        $this->assertFalse($gns->has(GeneralName::TAG_URI));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOf(GeneralNames $gns)
    {
        $this->assertCount(2, $gns->allOf(GeneralName::TAG_DNS_NAME));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstOf(GeneralNames $gns)
    {
        $this->assertInstanceOf(DNSName::class, $gns->firstOf(GeneralName::TAG_DNS_NAME));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstOfFail(GeneralNames $gns)
    {
        $this->expectException(UnexpectedValueException::class);
        $gns->firstOf(GeneralName::TAG_URI);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(GeneralNames $gns)
    {
        $this->assertCount(2, $gns);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(GeneralNames $gns)
    {
        $values = [];
        foreach ($gns as $gn) {
            $values[] = $gn;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(GeneralName::class, $values);
    }

    /**
     * @test
     */
    public function fromEmptyFail()
    {
        $this->expectException(UnexpectedValueException::class);
        GeneralNames::fromASN1(new Sequence());
    }

    /**
     * @test
     */
    public function emptyToASN1Fail()
    {
        $gn = new GeneralNames();
        $this->expectException(LogicException::class);
        $gn->toASN1();
    }

    /**
     * @test
     */
    public function firstDNS()
    {
        $name = new DNSName('example.com');
        $gn = new GeneralNames($name);
        $this->assertEquals($name, $gn->firstDNS());
    }

    /**
     * @test
     */
    public function firstDN()
    {
        $name = DirectoryName::fromDNString('cn=Example');
        $gn = new GeneralNames($name);
        $this->assertEquals($name->dn(), $gn->firstDN());
    }

    /**
     * @test
     */
    public function firstURI()
    {
        $name = new UniformResourceIdentifier('urn:example');
        $gn = new GeneralNames($name);
        $this->assertEquals($name, $gn->firstURI());
    }

    /**
     * @test
     */
    public function firstDNSFail()
    {
        $gn = new GeneralNames(new GeneralNamesTest_NameMockup(GeneralName::TAG_DNS_NAME));
        $this->expectException(RuntimeException::class);
        $gn->firstDNS();
    }

    /**
     * @test
     */
    public function firstDNFail()
    {
        $gn = new GeneralNames(new GeneralNamesTest_NameMockup(GeneralName::TAG_DIRECTORY_NAME));
        $this->expectException(RuntimeException::class);
        $gn->firstDN();
    }

    /**
     * @test
     */
    public function firstURIFail()
    {
        $gn = new GeneralNames(new GeneralNamesTest_NameMockup(GeneralName::TAG_URI));
        $this->expectException(RuntimeException::class);
        $gn->firstURI();
    }
}

class GeneralNamesTest_NameMockup extends GeneralName
{
    public function __construct($tag)
    {
        $this->_tag = $tag;
    }

    public function string(): string
    {
        return '';
    }

    protected function _choiceASN1(): TaggedType
    {
        return new NullType();
    }
}
