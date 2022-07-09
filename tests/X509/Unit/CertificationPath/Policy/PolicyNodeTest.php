<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\CertificationPath\Policy;

use PHPUnit\Framework\TestCase;
use Sop\X509\CertificationPath\Policy\PolicyNode;

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
        $node = new PolicyNode('1.3.6.1.3', [], []);
        $this->assertInstanceOf(PolicyNode::class, $node);
    }

    /**
     * @test
     */
    public function hasChildWithPolicyMatch()
    {
        $node = PolicyNode::anyPolicyNode()->addChild(new PolicyNode('1.3.6.1.3', [], []));
        $this->assertTrue($node->hasChildWithValidPolicy('1.3.6.1.3'));
    }

    /**
     * @test
     */
    public function parent()
    {
        $root = PolicyNode::anyPolicyNode();
        $child = new PolicyNode('1.3.6.1.3', [], []);
        $root->addChild($child);
        $this->assertEquals($root, $child->parent());
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
        $this->assertContainsOnlyInstancesOf(PolicyNode::class, $nodes);
    }
}
