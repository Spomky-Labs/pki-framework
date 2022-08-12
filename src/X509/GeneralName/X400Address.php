<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\GeneralName;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements *x400Address* CHOICE type of *GeneralName*.
 *
 * Currently acts as a parking object for decoding.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 *
 * @todo Implement ORAddress type
 */
final class X400Address extends GeneralName
{
    /**
     * @var Element
     */
    protected $_element;

    protected function __construct()
    {
        $this->_tag = self::TAG_X400_ADDRESS;
    }

    /**
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        $obj = new self();
        $obj->_element = $el->asSequence();
        return $obj;
    }

    public function string(): string
    {
        return bin2hex($this->_element->toDER());
    }

    protected function _choiceASN1(): TaggedType
    {
        return ImplicitlyTaggedType::create($this->_tag, $this->_element);
    }
}
