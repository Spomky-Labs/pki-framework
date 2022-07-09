<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Constructed;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Structure;

/**
 * Implements *SET* and *SET OF* types.
 */
final class Set extends Structure
{
    /**
     * Constructor.
     *
     * @param Element ...$elements Any number of elements
     */
    public function __construct(Element ...$elements)
    {
        $this->_typeTag = self::TYPE_SET;
        parent::__construct(...$elements);
    }

    /**
     * Sort by canonical ascending order.
     *
     * Used for DER encoding of *SET* type.
     */
    public function sortedSet(): self
    {
        $obj = clone $this;
        usort(
            $obj->_elements,
            function (Element $a, Element $b) {
                if ($a->typeClass() !== $b->typeClass()) {
                    return $a->typeClass() < $b->typeClass() ? -1 : 1;
                }
                return $a->tag() <=> $b->tag();
            }
        );
        return $obj;
    }

    /**
     * Sort by encoding ascending order.
     *
     * Used for DER encoding of *SET OF* type.
     */
    public function sortedSetOf(): self
    {
        $obj = clone $this;
        usort(
            $obj->_elements,
            function (Element $a, Element $b) {
                $a_der = $a->toDER();
                $b_der = $b->toDER();
                return strcmp($a_der, $b_der);
            }
        );
        return $obj;
    }
}
