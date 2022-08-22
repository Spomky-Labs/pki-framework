<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath\Policy;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X509\CertificationPath\Policy\PolicyNode;

/**
 * @internal
 */
final class PolicyNodeTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $node = PolicyNode::create('1.3.6.1.3', [], []);
        static::assertInstanceOf(PolicyNode::class, $node);
    }

    /**
     * @test
     */
    public function hasChildWithPolicyMatch()
    {
        $node = PolicyNode::anyPolicyNode()->addChild(PolicyNode::create('1.3.6.1.3', [], []));
        static::assertTrue($node->hasChildWithValidPolicy('1.3.6.1.3'));
    }

    /**
     * @test
     */
    public function parent()
    {
        $root = PolicyNode::anyPolicyNode();
        $child = PolicyNode::create('1.3.6.1.3', [], []);
        $root->addChild($child);
        static::assertEquals($root, $child->parent());
    }

    /**
     * @test
     */
    public function iterator()
    {
        $node = PolicyNode::anyPolicyNode()->addChild(
            PolicyNode::anyPolicyNode()
        )->addChild(PolicyNode::anyPolicyNode());
        $nodes = [];
        foreach ($node as $child) {
            $nodes[] = $child;
        }
        static::assertContainsOnlyInstancesOf(PolicyNode::class, $nodes);
    }
}
