<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension\Target;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

/**
 * Implements 'targetName' CHOICE of the *Target* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
final class TargetName extends Target
{
    public function __construct(/**
     * Name.
     */
        protected GeneralName $_name
    ) {
        $this->_type = self::TYPE_NAME;
    }

    /**
     * @return self
     */
    public static function fromChosenASN1(TaggedType $el): Target
    {
        return new self(GeneralName::fromASN1($el));
    }

    public function string(): string
    {
        return $this->_name->string();
    }

    public function name(): GeneralName
    {
        return $this->_name;
    }

    public function toASN1(): Element
    {
        return new ExplicitlyTaggedType($this->_type, $this->_name->toASN1());
    }
}
