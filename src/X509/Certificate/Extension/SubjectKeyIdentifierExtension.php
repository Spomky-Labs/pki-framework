<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements 'Subject Key Identifier' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.2
 */
final class SubjectKeyIdentifierExtension extends Extension
{
    public function __construct(
        bool $critical, /**
     * Key identifier.
     */
        protected string $_keyIdentifier
    ) {
        parent::__construct(self::OID_SUBJECT_KEY_IDENTIFIER, $critical);
    }

    /**
     * Get key identifier.
     */
    public function keyIdentifier(): string
    {
        return $this->_keyIdentifier;
    }

    protected static function _fromDER(string $data, bool $critical): static
    {
        return new self($critical, UnspecifiedType::fromDER($data)->asOctetString()->string());
    }

    protected function _valueASN1(): Element
    {
        return new OctetString($this->_keyIdentifier);
    }
}
