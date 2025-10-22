<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath\Policy;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SpomkyLabs\Pki\X509\CertificationPath\Policy\PolicyNode;
use SpomkyLabs\Pki\X509\CertificationPath\Policy\PolicyTree;

/**
 * @internal
 */
final class PolicyTreeTest extends TestCase
{
    /**
     * Cover edge case where root node is pruned.
     */
    #[Test]
    public function nodesAtDepthNoRoot()
    {
        $tree = PolicyTree::create(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty('root');
        $prop->setValue($tree, null);
        static::assertEmpty($tree->policiesAtDepth(1));
    }

    /**
     * Cover edge case where root node is pruned.
     */
    #[Test]
    public function validPolicyNodeSetNoRoot()
    {
        $tree = PolicyTree::create(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty('root');
        $prop->setValue($tree, null);
        $mtd = $obj->getMethod('validPolicyNodeSet');
        static::assertEmpty($mtd->invoke($tree));
    }

    /**
     * Cover edge case where root node is pruned.
     */
    #[Test]
    public function pruneNoRoot()
    {
        $tree = PolicyTree::create(PolicyNode::anyPolicyNode());
        $obj = new ReflectionClass($tree);
        $prop = $obj->getProperty('root');
        $prop->setValue($tree, null);
        $mtd = $obj->getMethod('pruneTree');
        static::assertSame(0, $mtd->invoke($tree, 0));
    }
}
