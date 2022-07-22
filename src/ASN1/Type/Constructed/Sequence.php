<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Constructed;

use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;
use SpomkyLabs\Pki\ASN1\Type\Structure;

/**
 * Implements *SEQUENCE* and *SEQUENCE OF* types.
 */
final class Sequence extends Structure
{
    /**
     * @param ElementBase ...$elements Any number of elements
     */
    private function __construct(ElementBase ...$elements)
    {
        $this->_typeTag = self::TYPE_SEQUENCE;
        parent::__construct(...$elements);
    }

    /**
     * @param Element ...$elements Any number of elements
     */
    public static function create(Element ...$elements): self
    {
        return new self(...$elements);
    }

    /**
     * @return self
     */
    protected static function decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        if (! $identifier->isConstructed()) {
            throw new DecodeException('Structured element must have constructed bit set.');
        }
        $idx = $offset;
        $length = Length::expectFromDER($data, $idx);
        if ($length->isIndefinite()) {
            $type = self::decodeIndefiniteLength($data, $idx);
        } else {
            $type = self::decodeDefiniteLength($data, $idx, $length->intLength());
        }
        $offset = $idx;
        return $type;
    }

    /**
     * Decode elements for a definite length.
     *
     * @param string $data DER data
     * @param int $offset Offset to data
     * @param int $length Number of bytes to decode
     */
    protected static function decodeDefiniteLength(string $data, int &$offset, int $length): ElementBase
    {
        $idx = $offset;
        $end = $idx + $length;
        $elements = [];
        while ($idx < $end) {
            $elements[] = Element::fromDER($data, $idx);
            // check that element didn't overflow length
            if ($idx > $end) {
                throw new DecodeException("Structure's content overflows length.");
            }
        }
        $offset = $idx;
        // return instance by static late binding
        return new self(...$elements);
    }

    /**
     * Decode elements for an indefinite length.
     *
     * @param string $data DER data
     * @param int $offset Offset to data
     */
    protected static function decodeIndefiniteLength(string $data, int &$offset): ElementBase
    {
        $idx = $offset;
        $elements = [];
        $end = mb_strlen($data, '8bit');
        while (true) {
            if ($idx >= $end) {
                throw new DecodeException('Unexpected end of data while decoding indefinite length structure.');
            }
            $el = Element::fromDER($data, $idx);
            if ($el->isType(self::TYPE_EOC)) {
                break;
            }
            $elements[] = $el;
        }
        $offset = $idx;
        $type = new self(...$elements);
        $type->_indefiniteLength = true;
        return $type;
    }
}
