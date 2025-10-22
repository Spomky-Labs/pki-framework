<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\NameConstraints;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\RFC822Name;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class GeneralSubtreeTest extends TestCase
{
    public const URI = '.example.com';

    #[Test]
    public function create(): GeneralSubtree
    {
        $subtree = GeneralSubtree::create(UniformResourceIdentifier::create(self::URI));
        static::assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    #[Test]
    #[Depends('create')]
    public function encode(GeneralSubtree $subtree): string
    {
        $el = $subtree->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): GeneralSubtree
    {
        $subtree = GeneralSubtree::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(GeneralSubtree $ref, GeneralSubtree $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function base(GeneralSubtree $subtree)
    {
        $base = $subtree->base();
        static::assertInstanceOf(GeneralName::class, $base);
    }

    #[Test]
    public function createWithAll()
    {
        $subtree = GeneralSubtree::create(UniformResourceIdentifier::create(self::URI), 1, 3);
        static::assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    #[Test]
    #[Depends('createWithAll')]
    public function encodeWithAll(GeneralSubtree $subtree)
    {
        $el = $subtree->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encodeWithAll')]
    public function decodeWithAll($data)
    {
        $subtree = GeneralSubtree::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    #[Test]
    #[Depends('createWithAll')]
    #[Depends('decodeWithAll')]
    public function recodedWithAll(GeneralSubtree $ref, GeneralSubtree $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * Test for GeneralName tag that collide with other GeneralSubtree tags.
     */
    #[Test]
    public function collidingTag()
    {
        $subtree = GeneralSubtree::create(RFC822Name::create('test'));
        $asn1 = $subtree->toASN1();
        $result = GeneralSubtree::fromASN1($asn1);
        static::assertInstanceOf(GeneralSubtree::class, $result);
    }
}
