<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\NameConstraints;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class GeneralSubtreesTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $subtrees = new GeneralSubtrees(
            new GeneralSubtree(new UniformResourceIdentifier('.example.com')),
            new GeneralSubtree(DirectoryName::fromDNString('cn=Test'))
        );
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(GeneralSubtrees $subtrees)
    {
        $el = $subtrees->toASN1();
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
        $subtrees = GeneralSubtrees::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(GeneralSubtrees $ref, GeneralSubtrees $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(GeneralSubtrees $subtrees)
    {
        $this->assertContainsOnlyInstancesOf(GeneralSubtree::class, $subtrees->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(GeneralSubtrees $subtrees)
    {
        $this->assertCount(2, $subtrees);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(GeneralSubtrees $subtrees)
    {
        $values = [];
        foreach ($subtrees as $subtree) {
            $values[] = $subtree;
        }
        $this->assertContainsOnlyInstancesOf(GeneralSubtree::class, $values);
    }

    /**
     * @test
     */
    public function decodeEmptyFail()
    {
        $this->expectException(UnexpectedValueException::class);
        GeneralSubtrees::fromASN1(new Sequence());
    }

    /**
     * @test
     */
    public function encodeEmptyFail()
    {
        $subtrees = new GeneralSubtrees();
        $this->expectException(LogicException::class);
        $subtrees->toASN1();
    }
}
