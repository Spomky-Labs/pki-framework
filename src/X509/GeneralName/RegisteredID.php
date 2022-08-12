<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\GeneralName;

use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements *registeredID* CHOICE type of *GeneralName*.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
final class RegisteredID extends GeneralName
{
    /**
     * @param string $_oid OID in dotted format
     */
    public function __construct(protected string $_oid)
    {
        $this->_tag = self::TAG_REGISTERED_ID;
    }

    /**
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        return new self($el->asObjectIdentifier()->oid());
    }

    public function string(): string
    {
        return $this->_oid;
    }

    /**
     * Get object identifier in dotted format.
     *
     * @return string OID
     */
    public function oid(): string
    {
        return $this->_oid;
    }

    protected function _choiceASN1(): TaggedType
    {
        return ImplicitlyTaggedType::create($this->_tag, ObjectIdentifier::create($this->_oid));
    }
}
