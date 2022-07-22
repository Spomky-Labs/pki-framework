<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\GeneralName;

use SpomkyLabs\Pki\ASN1\Type\Primitive\IA5String;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements *dNSName* CHOICE type of *GeneralName*.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
final class DNSName extends GeneralName
{
    /**
     * @param string $_name Domain name
     */
    public function __construct(protected string $_name)
    {
        $this->_tag = self::TAG_DNS_NAME;
    }

    /**
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        return new self($el->asIA5String()->string());
    }

    public function string(): string
    {
        return $this->_name;
    }

    /**
     * Get DNS name.
     */
    public function name(): string
    {
        return $this->_name;
    }

    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag, new IA5String($this->_name));
    }
}
