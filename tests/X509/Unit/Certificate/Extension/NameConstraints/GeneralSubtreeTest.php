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

    public function testCreate()
    {
        $subtree = new GeneralSubtree(new UniformResourceIdentifier(self::URI));
        $this->assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(GeneralSubtree $subtree)
    {
        $el = $subtree->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $subtree = GeneralSubtree::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(GeneralSubtree $ref, GeneralSubtree $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testBase(GeneralSubtree $subtree)
    {
        $base = $subtree->base();
        $this->assertInstanceOf(GeneralName::class, $base);
    }

    public function testCreateWithAll()
    {
        $subtree = new GeneralSubtree(new UniformResourceIdentifier(self::URI), 1, 3);
        $this->assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    /**
     * @depends testCreateWithAll
     */
    public function testEncodeWithAll(GeneralSubtree $subtree)
    {
        $el = $subtree->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncodeWithAll
     *
     * @param string $data
     */
    public function testDecodeWithAll($data)
    {
        $subtree = GeneralSubtree::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(GeneralSubtree::class, $subtree);
        return $subtree;
    }

    /**
     * @depends testCreateWithAll
     * @depends testDecodeWithAll
     */
    public function testRecodedWithAll(GeneralSubtree $ref, GeneralSubtree $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * Test for GeneralName tag that collide with other GeneralSubtree tags.
     */
    public function testCollidingTag()
    {
        $subtree = new GeneralSubtree(new RFC822Name('test'));
        $asn1 = $subtree->toASN1();
        $result = GeneralSubtree::fromASN1($asn1);
        $this->assertInstanceOf(GeneralSubtree::class, $result);
    }
}
