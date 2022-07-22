<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints;

use function count;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

/**
 * Implements *GeneralSubtree* ASN.1 type used by 'Name Constraints' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.10
 */
final class GeneralSubtree
{
    public function __construct(
        /**
         * Constraint.
         */
        protected GeneralName $_base,
        /**
         * Not used, must be zero.
         */
        protected int $_min = 0,
        /**
         * Not used, must be null.
         */
        protected ?int $_max = null
    ) {
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $base = GeneralName::fromASN1($seq->at(0)->asTagged());
        $min = 0;
        $max = null;
        // GeneralName is a CHOICE, which may be tagged as otherName [0]
        // or rfc822Name [1]. As minimum and maximum are also implicitly tagged,
        // we have to iterate the remaining elements instead of just checking
        // for tagged types.
        for ($i = 1; $i < count($seq); ++$i) {
            $el = $seq->at($i)
                ->expectTagged();
            switch ($el->tag()) {
                case 0:
                    $min = $el->asImplicit(Element::TYPE_INTEGER)
                        ->asInteger()
                        ->intNumber();
                    break;
                case 1:
                    $max = $el->asImplicit(Element::TYPE_INTEGER)
                        ->asInteger()
                        ->intNumber();
                    break;
            }
        }
        return new self($base, $min, $max);
    }

    public function base(): GeneralName
    {
        return $this->_base;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [$this->_base->toASN1()];
        if (isset($this->_min) && $this->_min !== 0) {
            $elements[] = new ImplicitlyTaggedType(0, new Integer($this->_min));
        }
        if (isset($this->_max)) {
            $elements[] = new ImplicitlyTaggedType(1, new Integer($this->_max));
        }
        return Sequence::create(...$elements);
    }
}
