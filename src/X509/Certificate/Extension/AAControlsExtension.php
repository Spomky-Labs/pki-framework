<?php

declare(strict_types=1);

namespace Sop\X509\Certificate\Extension;

use LogicException;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Implements 'AA Controls' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-7.4
 */
final class AAControlsExtension extends Extension
{
    /**
     * Constructor.
     *
     * @param null|string[] $_permittedAttrs
     * @param null|string[] $_excludedAttrs
     */
    public function __construct(
        bool $critical,
        /**
         * Path length contraint.
         */
        protected ?int $_pathLenConstraint = null,
        /**
         * Permitted attributes.
         *
         * Array of OID's.
         */
        protected ?array $_permittedAttrs = null,
        /**
         * Excluded attributes.
         *
         * Array of OID's.
         */
        protected ?array $_excludedAttrs = null,
        /**
         * Whether to permit unspecified attributes.
         */
        protected bool $_permitUnSpecified = true
    ) {
        parent::__construct(self::OID_AA_CONTROLS, $critical);
    }

    /**
     * Check whether path length constraint is present.
     */
    public function hasPathLen(): bool
    {
        return isset($this->_pathLenConstraint);
    }

    /**
     * Get path length constraint.
     */
    public function pathLen(): int
    {
        if (! $this->hasPathLen()) {
            throw new LogicException('pathLen not set.');
        }
        return $this->_pathLenConstraint;
    }

    /**
     * Check whether permitted attributes are present.
     */
    public function hasPermittedAttrs(): bool
    {
        return isset($this->_permittedAttrs);
    }

    /**
     * Get OID's of permitted attributes.
     *
     * @return string[]
     */
    public function permittedAttrs(): array
    {
        if (! $this->hasPermittedAttrs()) {
            throw new LogicException('permittedAttrs not set.');
        }
        return $this->_permittedAttrs;
    }

    /**
     * Check whether excluded attributes are present.
     */
    public function hasExcludedAttrs(): bool
    {
        return isset($this->_excludedAttrs);
    }

    /**
     * Get OID's of excluded attributes.
     *
     * @return string[]
     */
    public function excludedAttrs(): array
    {
        if (! $this->hasExcludedAttrs()) {
            throw new LogicException('excludedAttrs not set.');
        }
        return $this->_excludedAttrs;
    }

    /**
     * Whether to permit attributes that are not explicitly specified in neither permitted nor excluded list.
     */
    public function permitUnspecified(): bool
    {
        return $this->_permitUnSpecified;
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $seq = UnspecifiedType::fromDER($data)->asSequence();
        $path_len = null;
        $permitted = null;
        $excluded = null;
        $permit_unspecified = true;
        $idx = 0;
        if ($seq->has($idx, Element::TYPE_INTEGER)) {
            $path_len = $seq->at($idx++)
                ->asInteger()
                ->intNumber();
        }
        if ($seq->hasTagged(0)) {
            $attr_seq = $seq->getTagged(0)
                ->asImplicit(Element::TYPE_SEQUENCE)
                ->asSequence();
            $permitted = array_map(
                fn (UnspecifiedType $el) => $el->asObjectIdentifier()
                    ->oid(),
                $attr_seq->elements()
            );
            ++$idx;
        }
        if ($seq->hasTagged(1)) {
            $attr_seq = $seq->getTagged(1)
                ->asImplicit(Element::TYPE_SEQUENCE)
                ->asSequence();
            $excluded = array_map(
                fn (UnspecifiedType $el) => $el->asObjectIdentifier()
                    ->oid(),
                $attr_seq->elements()
            );
            ++$idx;
        }
        if ($seq->has($idx, Element::TYPE_BOOLEAN)) {
            $permit_unspecified = $seq->at($idx++)
                ->asBoolean()
                ->value();
        }
        return new self($critical, $path_len, $permitted, $excluded, $permit_unspecified);
    }

    protected function _valueASN1(): Element
    {
        $elements = [];
        if (isset($this->_pathLenConstraint)) {
            $elements[] = new Integer($this->_pathLenConstraint);
        }
        if (isset($this->_permittedAttrs)) {
            $oids = array_map(fn ($oid) => new ObjectIdentifier($oid), $this->_permittedAttrs);
            $elements[] = new ImplicitlyTaggedType(0, new Sequence(...$oids));
        }
        if (isset($this->_excludedAttrs)) {
            $oids = array_map(fn ($oid) => new ObjectIdentifier($oid), $this->_excludedAttrs);
            $elements[] = new ImplicitlyTaggedType(1, new Sequence(...$oids));
        }
        if (true !== $this->_permitUnSpecified) {
            $elements[] = new Boolean(false);
        }
        return new Sequence(...$elements);
    }
}
