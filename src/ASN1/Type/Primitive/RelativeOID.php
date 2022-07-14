<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;

/**
 * Implements *RELATIVE-OID* type.
 */
final class RelativeOID extends ObjectIdentifier
{
    /**
     * Constructor.
     *
     * @param string $oid OID in dotted format
     */
    public function __construct(string $oid)
    {
        $this->_oid = $oid;
        $this->_subids = self::_explodeDottedOID($oid);
        $this->_typeTag = self::TYPE_RELATIVE_OID;
    }

    protected function encodedAsDER(): string
    {
        return self::_encodeSubIDs(...$this->_subids);
    }

    protected static function decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        $idx = $offset;
        $len = Length::expectFromDER($data, $idx)->intLength();
        $subids = self::_decodeSubIDs(mb_substr($data, $idx, $len, '8bit'));
        $offset = $idx + $len;
        return new self(self::_implodeSubIDs(...$subids));
    }
}
