<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension;

use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements 'Basic Constraints' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.9
 */
final class BasicConstraintsExtension extends Extension
{
    public function __construct(
        bool $critical, /**
     * Whether certificate is a CA.
     */
        protected bool $_ca, /**
     * Maximum certification path length.
     */
        protected ?int $_pathLen = null
    ) {
        parent::__construct(self::OID_BASIC_CONSTRAINTS, $critical);
    }

    /**
     * Whether certificate is a CA.
     */
    public function isCA(): bool
    {
        return $this->_ca;
    }

    /**
     * Whether path length is present.
     */
    public function hasPathLen(): bool
    {
        return isset($this->_pathLen);
    }

    /**
     * Get path length.
     */
    public function pathLen(): int
    {
        if (! $this->hasPathLen()) {
            throw new LogicException('pathLenConstraint not set.');
        }
        return $this->_pathLen;
    }

    protected static function _fromDER(string $data, bool $critical): static
    {
        $seq = UnspecifiedType::fromDER($data)->asSequence();
        $ca = false;
        $path_len = null;
        $idx = 0;
        if ($seq->has($idx, Element::TYPE_BOOLEAN)) {
            $ca = $seq->at($idx++)
                ->asBoolean()
                ->value();
        }
        if ($seq->has($idx, Element::TYPE_INTEGER)) {
            $path_len = $seq->at($idx)
                ->asInteger()
                ->intNumber();
        }
        return new self($critical, $ca, $path_len);
    }

    protected function _valueASN1(): Element
    {
        $elements = [];
        if ($this->_ca) {
            $elements[] = new Boolean(true);
        }
        if (isset($this->_pathLen)) {
            $elements[] = new Integer($this->_pathLen);
        }
        return Sequence::create(...$elements);
    }
}
