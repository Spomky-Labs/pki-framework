<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\CertificationPath\Policy;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Sop\X509\CertificationPath\Policy\PolicyNode;
use Sop\X509\CertificationPath\Policy\PolicyTree;

/**
 * @internal
 */
final class PolicyTreeTest extends TestCase
{
    /**
     * Cover edge case where root node is pruned.
     *
     * @test
     */
    public function nodesAtDepthNoRoot()
    {
        $tree = new PolicyTree(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty('_root');
        $prop->setAccessible(true);
        $prop->setValue($tree, null);
        $this->assertEmpty($tree->policiesAtDepth(1));
    }

    /**
     * Cover edge case where root node is pruned.
     *
     * @test
     */
    public function validPolicyNodeSetNoRoot()
    {
        $tree = new PolicyTree(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty('_root');
        $prop->setAccessible(true);
        $prop->setValue($tree, null);
        $mtd = $obj->getMethod('_validPolicyNodeSet');
        $mtd->setAccessible(true);
        $this->assertEmpty($mtd->invoke($tree));
    }

    /**
     * Cover edge case where root node is pruned.
     *
     * @test
     */
    public function pruneNoRoot()
    {
        $tree = new PolicyTree(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty('_root');
        $prop->setAccessible(true);
        $prop->setValue($tree, null);
        $mtd = $obj->getMethod('_pruneTree');
        $mtd->setAccessible(true);
        $this->assertEquals(0, $mtd->invoke($tree, 0));
    }
}
