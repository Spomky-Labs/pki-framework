<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\GeneralName;

use SpomkyLabs\Pki\ASN1\Type\Primitive\IA5String;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements *uniformResourceIdentifier* CHOICE type of *GeneralName*.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
final class UniformResourceIdentifier extends GeneralName
{
    public function __construct(/**
     * URI.
     */
        protected string $_uri
    ) {
        $this->_tag = self::TAG_URI;
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
        return $this->_uri;
    }

    public function uri(): string
    {
        return $this->_uri;
    }

    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag, IA5String::create($this->_uri));
    }
}
