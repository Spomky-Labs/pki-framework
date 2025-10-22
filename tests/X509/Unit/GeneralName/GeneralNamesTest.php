<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use BadMethodCallException;
use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): GeneralNames
    {
        $gns = GeneralNames::create(DNSName::create('test1'), DNSName::create('test2'));
        static::assertInstanceOf(GeneralNames::class, $gns);
        return $gns;
    }

    #[Test]
    #[Depends('create')]
    public function encode(GeneralNames $gns): string
    {
        $seq = $gns->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): GeneralNames
    {
        $gns = GeneralNames::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(GeneralNames::class, $gns);
        return $gns;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(GeneralNames $ref, GeneralNames $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function has(GeneralNames $gns)
    {
        static::assertTrue($gns->has(GeneralName::TAG_DNS_NAME));
    }

    #[Test]
    #[Depends('create')]
    public function hasNot(GeneralNames $gns)
    {
        static::assertFalse($gns->has(GeneralName::TAG_URI));
    }

    #[Test]
    #[Depends('create')]
    public function allOf(GeneralNames $gns)
    {
        static::assertCount(2, $gns->allOf(GeneralName::TAG_DNS_NAME));
    }

    #[Test]
    #[Depends('create')]
    public function firstOf(GeneralNames $gns)
    {
        static::assertInstanceOf(DNSName::class, $gns->firstOf(GeneralName::TAG_DNS_NAME));
    }

    #[Test]
    #[Depends('create')]
    public function firstOfFail(GeneralNames $gns)
    {
        $this->expectException(UnexpectedValueException::class);
        $gns->firstOf(GeneralName::TAG_URI);
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(GeneralNames $gns)
    {
        static::assertCount(2, $gns);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(GeneralNames $gns)
    {
        $values = [];
        foreach ($gns as $gn) {
            $values[] = $gn;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(GeneralName::class, $values);
    }

    #[Test]
    public function fromEmptyFail()
    {
        $this->expectException(UnexpectedValueException::class);
        GeneralNames::fromASN1(Sequence::create());
    }

    #[Test]
    public function emptyToASN1Fail()
    {
        $gn = GeneralNames::create();
        $this->expectException(LogicException::class);
        $gn->toASN1();
    }

    #[Test]
    public function firstDNS()
    {
        $name = DNSName::create('example.com');
        $gn = GeneralNames::create($name);
        static::assertEquals($name, $gn->firstDNS());
    }

    #[Test]
    public function firstDN()
    {
        $name = DirectoryName::fromDNString('cn=Example');
        $gn = GeneralNames::create($name);
        static::assertEquals($name->dn(), $gn->firstDN());
    }

    #[Test]
    public function firstURI()
    {
        $name = UniformResourceIdentifier::create('urn:example');
        $gn = GeneralNames::create($name);
        static::assertEquals($name, $gn->firstURI());
    }

    #[Test]
    public function firstDNSFail()
    {
        $gn = GeneralNames::create(GeneralNamesTest_NameMockup::create(GeneralName::TAG_DNS_NAME));
        $this->expectException(RuntimeException::class);
        $gn->firstDNS();
    }

    #[Test]
    public function firstDNFail()
    {
        $gn = GeneralNames::create(GeneralNamesTest_NameMockup::create(GeneralName::TAG_DIRECTORY_NAME));
        $this->expectException(RuntimeException::class);
        $gn->firstDN();
    }

    #[Test]
    public function firstURIFail()
    {
        $gn = GeneralNames::create(GeneralNamesTest_NameMockup::create(GeneralName::TAG_URI));
        $this->expectException(RuntimeException::class);
        $gn->firstURI();
    }
}

class GeneralNamesTest_NameMockup extends GeneralName
{
    public static function create(int $tag): self
    {
        return new self($tag);
    }

    public function string(): string
    {
        return '';
    }

    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in the derived class.');
    }

    protected function choiceASN1(): TaggedType
    {
        return NullType::create();
    }
}
