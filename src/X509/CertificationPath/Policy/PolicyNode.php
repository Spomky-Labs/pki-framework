<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\CertificationPath\Policy;

use ArrayIterator;
use function count;
use Countable;
use function in_array;
use IteratorAggregate;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;

/**
 * Policy node class for certification path validation.
 *
 * @internal Mutable class used by PolicyTree
 *
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.2
 */
final class PolicyNode implements IteratorAggregate, Countable
{
    /**
     * List of child nodes.
     *
     * @var PolicyNode[]
     */
    private array $_children;

    /**
     * Reference to the parent node.
     *
     * @var null|PolicyNode
     */
    private $_parent;

    /**
     * @param string $_validPolicy Policy OID
     * @param PolicyQualifierInfo[] $_qualifiers
     * @param string[] $_expectedPolicies
     */
    public function __construct(
        private readonly string $_validPolicy, /**
     * List of qualifiers.
     */
        private readonly array $_qualifiers, /**
     * List of expected policy OIDs.
     */
        private array $_expectedPolicies
    ) {
        $this->_children = [];
    }

    /**
     * Create initial node for the policy tree.
     */
    public static function anyPolicyNode(): self
    {
        return new self(PolicyInformation::OID_ANY_POLICY, [], [PolicyInformation::OID_ANY_POLICY]);
    }

    /**
     * Get the valid policy OID.
     */
    public function validPolicy(): string
    {
        return $this->_validPolicy;
    }

    /**
     * Check whether node has anyPolicy as a valid policy.
     */
    public function isAnyPolicy(): bool
    {
        return $this->_validPolicy === PolicyInformation::OID_ANY_POLICY;
    }

    /**
     * Get the qualifier set.
     *
     * @return PolicyQualifierInfo[]
     */
    public function qualifiers(): array
    {
        return $this->_qualifiers;
    }

    /**
     * Check whether node has OID as an expected policy.
     */
    public function hasExpectedPolicy(string $oid): bool
    {
        return in_array($oid, $this->_expectedPolicies, true);
    }

    /**
     * Get the expected policy set.
     *
     * @return string[]
     */
    public function expectedPolicies(): array
    {
        return $this->_expectedPolicies;
    }

    /**
     * Set expected policies.
     *
     * @param string ...$oids Policy OIDs
     */
    public function setExpectedPolicies(string ...$oids): void
    {
        $this->_expectedPolicies = $oids;
    }

    /**
     * Check whether node has a child node with given valid policy OID.
     */
    public function hasChildWithValidPolicy(string $oid): bool
    {
        foreach ($this->_children as $node) {
            if ($node->validPolicy() === $oid) {
                return true;
            }
        }
        return false;
    }

    /**
     * Add child node.
     */
    public function addChild(self $node): self
    {
        $id = spl_object_hash($node);
        $node->_parent = $this;
        $this->_children[$id] = $node;
        return $this;
    }

    /**
     * Get the child nodes.
     *
     * @return PolicyNode[]
     */
    public function children(): array
    {
        return array_values($this->_children);
    }

    /**
     * Remove this node from the tree.
     *
     * @return self The removed node
     */
    public function remove(): self
    {
        if ($this->_parent) {
            $id = spl_object_hash($this);
            unset($this->_parent->_children[$id], $this->_parent);
        }
        return $this;
    }

    /**
     * Check whether node has a parent.
     */
    public function hasParent(): bool
    {
        return isset($this->_parent);
    }

    /**
     * Get the parent node.
     */
    public function parent(): ?self
    {
        return $this->_parent;
    }

    /**
     * Get chain of parent nodes from this node's parent to the root node.
     *
     * @return PolicyNode[]
     */
    public function parents(): array
    {
        if (! $this->_parent) {
            return [];
        }
        $nodes = $this->_parent->parents();
        $nodes[] = $this->_parent;
        return array_reverse($nodes);
    }

    /**
     * Walk tree from this node, applying a callback for each node.
     *
     * Nodes are traversed depth-first and callback shall be applied post-order.
     */
    public function walkNodes(callable $fn): void
    {
        foreach ($this->_children as $node) {
            $node->walkNodes($fn);
        }
        $fn($this);
    }

    /**
     * Get the total number of nodes in a tree.
     */
    public function nodeCount(): int
    {
        $c = 1;
        foreach ($this->_children as $child) {
            $c += $child->nodeCount();
        }
        return $c;
    }

    /**
     * Get the number of child nodes.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_children);
    }

    /**
     * Get iterator for the child nodes.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->_children);
    }
}
