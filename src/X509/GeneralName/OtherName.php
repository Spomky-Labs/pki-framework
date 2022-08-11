<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\GeneralName;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements *otherName* CHOICE type of *GeneralName*.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
final class OtherName extends GeneralName
{
    /**
     * @param string $_type OID
     */
    public function __construct(
        protected string $_type, /**
     * Value.
     */
        protected Element $_element
    ) {
        $this->_tag = self::TAG_OTHER_NAME;
    }

    /**
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        $seq = $el->asSequence();
        $type_id = $seq->at(0)
            ->asObjectIdentifier()
            ->oid();
        $value = $seq->getTagged(0)
            ->asExplicit()
            ->asElement();
        return new self($type_id, $value);
    }

    public function string(): string
    {
        return $this->_type . '/#' . bin2hex($this->_element->toDER());
    }

    /**
     * Get type OID.
     */
    public function type(): string
    {
        return $this->_type;
    }

    /**
     * Get value element.
     */
    public function value(): Element
    {
        return $this->_element;
    }

    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType(
            $this->_tag,
            Sequence::create(ObjectIdentifier::create($this->_type), new ExplicitlyTaggedType(0, $this->_element))
        );
    }
}
