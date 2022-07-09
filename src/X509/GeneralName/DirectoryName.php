<?php

declare(strict_types=1);

namespace Sop\X509\GeneralName;

use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\TaggedType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\Name;

/**
 * Implements *directoryName* CHOICE type of *GeneralName*.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
final class DirectoryName extends GeneralName
{
    public function __construct(
        protected Name $_dn
    ) {
        $this->_tag = self::TAG_DIRECTORY_NAME;
    }

    /**
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        return new self(Name::fromASN1($el->asSequence()));
    }

    /**
     * Initialize from distinguished name string.
     */
    public static function fromDNString(string $str): self
    {
        return new self(Name::fromString($str));
    }

    public function string(): string
    {
        return $this->_dn->toString();
    }

    /**
     * Get directory name.
     */
    public function dn(): Name
    {
        return $this->_dn;
    }

    protected function _choiceASN1(): TaggedType
    {
        // Name type is itself a CHOICE, so explicit tagging must be
        // employed to avoid ambiguities
        return new ExplicitlyTaggedType($this->_tag, $this->_dn->toASN1());
    }
}
