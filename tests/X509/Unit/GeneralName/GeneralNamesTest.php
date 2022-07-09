<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use BadMethodCallException;
use LogicException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;
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
        static::assertInstanceOf(GeneralNames::class, $gns);
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
        static::assertInstanceOf(Sequence::class, $seq);
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
        static::assertInstanceOf(GeneralNames::class, $gns);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function has(GeneralNames $gns)
    {
        static::assertTrue($gns->has(GeneralName::TAG_DNS_NAME));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNot(GeneralNames $gns)
    {
        static::assertFalse($gns->has(GeneralName::TAG_URI));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOf(GeneralNames $gns)
    {
        static::assertCount(2, $gns->allOf(GeneralName::TAG_DNS_NAME));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstOf(GeneralNames $gns)
    {
        static::assertInstanceOf(DNSName::class, $gns->firstOf(GeneralName::TAG_DNS_NAME));
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
        static::assertCount(2, $gns);
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
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(GeneralName::class, $values);
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
        static::assertEquals($name, $gn->firstDNS());
    }

    /**
     * @test
     */
    public function firstDN()
    {
        $name = DirectoryName::fromDNString('cn=Example');
        $gn = new GeneralNames($name);
        static::assertEquals($name->dn(), $gn->firstDN());
    }

    /**
     * @test
     */
    public function firstURI()
    {
        $name = new UniformResourceIdentifier('urn:example');
        $gn = new GeneralNames($name);
        static::assertEquals($name, $gn->firstURI());
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

    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in the derived class.');
    }

    protected function _choiceASN1(): TaggedType
    {
        return new NullType();
    }
}
