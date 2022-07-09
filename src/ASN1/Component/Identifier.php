<?php

declare(strict_types=1);

namespace Sop\ASN1\Component;

use function array_key_exists;
use GMP;
use function mb_strlen;
use function ord;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Feature\Encodable;
use Sop\ASN1\Util\BigInt;

/**
 * Class to represent BER/DER identifier octets.
 */
final class Identifier implements Encodable
{
    // Type class enumerations
    final public const CLASS_UNIVERSAL = 0b00;

    final public const CLASS_APPLICATION = 0b01;

    final public const CLASS_CONTEXT_SPECIFIC = 0b10;

    final public const CLASS_PRIVATE = 0b11;

    /**
     * Mapping from type class to human readable name.
     *
     * @internal
     *
     * @var array
     */
    final public const MAP_CLASS_TO_NAME = [
        self::CLASS_UNIVERSAL => 'UNIVERSAL',
        self::CLASS_APPLICATION => 'APPLICATION',
        self::CLASS_CONTEXT_SPECIFIC => 'CONTEXT SPECIFIC',
        self::CLASS_PRIVATE => 'PRIVATE',
    ];

    // P/C enumerations
    final public const PRIMITIVE = 0b0;

    final public const CONSTRUCTED = 0b1;

    /**
     * Type class.
     */
    private int $_class;

    /**
     * Primitive or Constructed.
     */
    private readonly int $_pc;

    /**
     * Content type tag.
     */
    private BigInt $_tag;

    /**
     * Constructor.
     *
     * @param int             $class Type class
     * @param int             $pc    Primitive / Constructed
     * @param GMP|int|string $tag   Type tag number
     */
    public function __construct(int $class, int $pc, $tag)
    {
        $this->_class = 0b11 & $class;
        $this->_pc = 0b1 & $pc;
        $this->_tag = new BigInt($tag);
    }

    /**
     * Decode identifier component from DER data.
     *
     * @param string   $data   DER encoded data
     * @param null|int $offset Reference to the variable that contains offset
     * into the data where to start parsing.
     * Variable is updated to the offset next to the
     * parsed identifier. If null, start from offset 0.
     */
    public static function fromDER(string $data, int &$offset = null): self
    {
        $idx = $offset ?? 0;
        $datalen = mb_strlen($data, '8bit');
        if ($idx >= $datalen) {
            throw new DecodeException('Invalid offset.');
        }
        $byte = ord($data[$idx++]);
        // bits 8 and 7 (class)
        // 0 = universal, 1 = application, 2 = context-specific, 3 = private
        $class = (0b11000000 & $byte) >> 6;
        // bit 6 (0 = primitive / 1 = constructed)
        $pc = (0b00100000 & $byte) >> 5;
        // bits 5 to 1 (tag number)
        $tag = (0b00011111 & $byte);
        // long-form identifier
        if ($tag === 0x1f) {
            $tag = self::_decodeLongFormTag($data, $idx);
        }
        if (isset($offset)) {
            $offset = $idx;
        }
        return new self($class, $pc, $tag);
    }

    public function toDER(): string
    {
        $bytes = [];
        $byte = $this->_class << 6 | $this->_pc << 5;
        $tag = $this->_tag->gmpObj();
        if ($tag < 0x1f) {
            $bytes[] = $byte | $tag;
        }
        // long-form identifier
        else {
            $bytes[] = $byte | 0x1f;
            $octets = [];
            for (; $tag > 0; $tag >>= 7) {
                array_push($octets, gmp_intval(0x80 | ($tag & 0x7f)));
            }
            // last octet has bit 8 set to zero
            $octets[0] &= 0x7f;
            foreach (array_reverse($octets) as $octet) {
                $bytes[] = $octet;
            }
        }
        return pack('C*', ...$bytes);
    }

    /**
     * Get class of the type.
     */
    public function typeClass(): int
    {
        return $this->_class;
    }

    public function pc(): int
    {
        return $this->_pc;
    }

    /**
     * Get the tag number.
     *
     * @return string Base 10 integer string
     */
    public function tag(): string
    {
        return $this->_tag->base10();
    }

    /**
     * Get the tag as an integer.
     */
    public function intTag(): int
    {
        return $this->_tag->intVal();
    }

    /**
     * Check whether type is of an universal class.
     */
    public function isUniversal(): bool
    {
        return $this->_class === self::CLASS_UNIVERSAL;
    }

    /**
     * Check whether type is of an application class.
     */
    public function isApplication(): bool
    {
        return $this->_class === self::CLASS_APPLICATION;
    }

    /**
     * Check whether type is of a context specific class.
     */
    public function isContextSpecific(): bool
    {
        return $this->_class === self::CLASS_CONTEXT_SPECIFIC;
    }

    /**
     * Check whether type is of a private class.
     */
    public function isPrivate(): bool
    {
        return $this->_class === self::CLASS_PRIVATE;
    }

    /**
     * Check whether content is primitive type.
     */
    public function isPrimitive(): bool
    {
        return $this->_pc === self::PRIMITIVE;
    }

    /**
     * Check hether content is constructed type.
     */
    public function isConstructed(): bool
    {
        return $this->_pc === self::CONSTRUCTED;
    }

    /**
     * Get self with given type class.
     *
     * @param int $class One of `CLASS_*` enumerations
     */
    public function withClass(int $class): self
    {
        $obj = clone $this;
        $obj->_class = 0b11 & $class;
        return $obj;
    }

    /**
     * Get self with given type tag.
     *
     * @param GMP|int|string $tag Tag number
     */
    public function withTag(GMP|int|string $tag): self
    {
        $obj = clone $this;
        $obj->_tag = new BigInt($tag);
        return $obj;
    }

    /**
     * Get human readable name of the type class.
     */
    public static function classToName(int $class): string
    {
        if (! array_key_exists($class, self::MAP_CLASS_TO_NAME)) {
            return "CLASS {$class}";
        }
        return self::MAP_CLASS_TO_NAME[$class];
    }

    /**
     * Parse long form tag.
     *
     * @param string $data   DER data
     * @param int    $offset Reference to the variable containing offset to data
     *
     * @return GMP Tag number
     */
    private static function _decodeLongFormTag(string $data, int &$offset): GMP
    {
        $datalen = mb_strlen($data, '8bit');
        $tag = gmp_init(0, 10);
        while (true) {
            if ($offset >= $datalen) {
                throw new DecodeException('Unexpected end of data while decoding long form identifier.');
            }
            $byte = ord($data[$offset++]);
            $tag <<= 7;
            $tag |= 0x7f & $byte;
            // last byte has bit 8 set to zero
            if (! (0x80 & $byte)) {
                break;
            }
        }
        return $tag;
    }
}
