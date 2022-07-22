<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension;

use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements 'Policy Constraints' certificate extensions.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.11
 */
final class PolicyConstraintsExtension extends Extension
{
    public function __construct(
        bool $critical,
        protected ?int $_requireExplicitPolicy = null,
        protected ?int $_inhibitPolicyMapping = null
    ) {
        parent::__construct(self::OID_POLICY_CONSTRAINTS, $critical);
    }

    /**
     * Whether requireExplicitPolicy is present.
     */
    public function hasRequireExplicitPolicy(): bool
    {
        return isset($this->_requireExplicitPolicy);
    }

    public function requireExplicitPolicy(): int
    {
        if (! $this->hasRequireExplicitPolicy()) {
            throw new LogicException('requireExplicitPolicy not set.');
        }
        return $this->_requireExplicitPolicy;
    }

    /**
     * Whether inhibitPolicyMapping is present.
     */
    public function hasInhibitPolicyMapping(): bool
    {
        return isset($this->_inhibitPolicyMapping);
    }

    public function inhibitPolicyMapping(): int
    {
        if (! $this->hasInhibitPolicyMapping()) {
            throw new LogicException('inhibitPolicyMapping not set.');
        }
        return $this->_inhibitPolicyMapping;
    }

    protected static function _fromDER(string $data, bool $critical): static
    {
        $seq = UnspecifiedType::fromDER($data)->asSequence();
        $require_explicit_policy = null;
        $inhibit_policy_mapping = null;
        if ($seq->hasTagged(0)) {
            $require_explicit_policy = $seq->getTagged(0)
                ->asImplicit(Element::TYPE_INTEGER)->asInteger()->intNumber();
        }
        if ($seq->hasTagged(1)) {
            $inhibit_policy_mapping = $seq->getTagged(1)
                ->asImplicit(Element::TYPE_INTEGER)->asInteger()->intNumber();
        }
        return new self($critical, $require_explicit_policy, $inhibit_policy_mapping);
    }

    protected function _valueASN1(): Element
    {
        $elements = [];
        if (isset($this->_requireExplicitPolicy)) {
            $elements[] = new ImplicitlyTaggedType(0, new Integer($this->_requireExplicitPolicy));
        }
        if (isset($this->_inhibitPolicyMapping)) {
            $elements[] = new ImplicitlyTaggedType(1, new Integer($this->_inhibitPolicyMapping));
        }
        return Sequence::create(...$elements);
    }
}
