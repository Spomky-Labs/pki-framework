<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

/**
 * @internal
 */
final class DirectoryNameTest extends TestCase
{
    #[Test]
    public function create(): DirectoryName
    {
        $name = DirectoryName::fromDNString('cn=Test');
        static::assertInstanceOf(DirectoryName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    public function encode(DirectoryName $name): string
    {
        $el = $name->toASN1();
        static::assertInstanceOf(ExplicitTagging::class, $el);
        return $el->toDER();
    }

    #[Test]
    #[Depends('encode')]
    public function choiceTag(string $der)
    {
        $el = TaggedType::fromDER($der);
        static::assertSame(GeneralName::TAG_DIRECTORY_NAME, $el->tag());
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $name = DirectoryName::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(DirectoryName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(DirectoryName $ref, DirectoryName $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function string(DirectoryName $name)
    {
        static::assertSame('cn=Test', $name->string());
    }

    #[Test]
    #[Depends('create')]
    public function dN(DirectoryName $name)
    {
        static::assertEquals(Name::fromString('cn=Test'), $name->dn());
    }
}
