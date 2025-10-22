<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\NameConstraints;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class GeneralSubtreesTest extends TestCase
{
    #[Test]
    public function create(): GeneralSubtrees
    {
        $subtrees = GeneralSubtrees::create(
            GeneralSubtree::create(UniformResourceIdentifier::create('.example.com')),
            GeneralSubtree::create(DirectoryName::fromDNString('cn=Test'))
        );
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    #[Test]
    #[Depends('create')]
    public function encode(GeneralSubtrees $subtrees): string
    {
        $el = $subtrees->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): GeneralSubtrees
    {
        $subtrees = GeneralSubtrees::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(GeneralSubtrees $ref, GeneralSubtrees $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function all(GeneralSubtrees $subtrees)
    {
        static::assertContainsOnlyInstancesOf(GeneralSubtree::class, $subtrees->all());
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(GeneralSubtrees $subtrees)
    {
        static::assertCount(2, $subtrees);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(GeneralSubtrees $subtrees)
    {
        $values = [];
        foreach ($subtrees as $subtree) {
            $values[] = $subtree;
        }
        static::assertContainsOnlyInstancesOf(GeneralSubtree::class, $values);
    }

    #[Test]
    public function decodeEmptyFail()
    {
        $this->expectException(UnexpectedValueException::class);
        GeneralSubtrees::fromASN1(Sequence::create());
    }

    #[Test]
    public function encodeEmptyFail()
    {
        $subtrees = GeneralSubtrees::create();
        $this->expectException(LogicException::class);
        $subtrees->toASN1();
    }
}
