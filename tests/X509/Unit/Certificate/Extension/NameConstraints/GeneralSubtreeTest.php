<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\NameConstraints;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\RFC822Name;
use Sop\X509\GeneralName\UniformResourceIdentifier;

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
        $this->assertInstanceOf(GeneralSubtree::class, $subtree);
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
        $this->assertInstanceOf(Sequence::class, $el);
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
        $this->assertInstanceOf(GeneralSubtree::class, $subtree);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function base(GeneralSubtree $subtree)
    {
        $base = $subtree->base();
        $this->assertInstanceOf(GeneralName::class, $base);
    }

    /**
     * @test
     */
    public function createWithAll()
    {
        $subtree = new GeneralSubtree(new UniformResourceIdentifier(self::URI), 1, 3);
        $this->assertInstanceOf(GeneralSubtree::class, $subtree);
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
        $this->assertInstanceOf(Sequence::class, $el);
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
        $this->assertInstanceOf(GeneralSubtree::class, $subtree);
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
        $this->assertEquals($ref, $new);
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
        $this->assertInstanceOf(GeneralSubtree::class, $result);
    }
}
