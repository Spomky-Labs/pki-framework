<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\NameConstraints;

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

    /**
     * @test
     */
    public function create()
    {
        $subtree = new GeneralSubtree(new UniformResourceIdentifier(self::URI));
        static::assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(GeneralSubtree $subtree)
    {
        $el = $subtree->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
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
        $subtree = GeneralSubtree::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(GeneralSubtree $ref, GeneralSubtree $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function base(GeneralSubtree $subtree)
    {
        $base = $subtree->base();
        static::assertInstanceOf(GeneralName::class, $base);
    }

    /**
     * @test
     */
    public function createWithAll()
    {
        $subtree = new GeneralSubtree(new UniformResourceIdentifier(self::URI), 1, 3);
        static::assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function encodeWithAll(GeneralSubtree $subtree)
    {
        $el = $subtree->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encodeWithAll
     *
     * @param string $data
     *
     * @test
     */
    public function decodeWithAll($data)
    {
        $subtree = GeneralSubtree::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    /**
     * @depends createWithAll
     * @depends decodeWithAll
     *
     * @test
     */
    public function recodedWithAll(GeneralSubtree $ref, GeneralSubtree $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * Test for GeneralName tag that collide with other GeneralSubtree tags.
     *
     * @test
     */
    public function collidingTag()
    {
        $subtree = new GeneralSubtree(new RFC822Name('test'));
        $asn1 = $subtree->toASN1();
        $result = GeneralSubtree::fromASN1($asn1);
        static::assertInstanceOf(GeneralSubtree::class, $result);
    }
}
