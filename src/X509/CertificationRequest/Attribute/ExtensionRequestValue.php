<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\CertificationRequest\Attribute;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\MatchingRule\BinaryMatch;
use SpomkyLabs\Pki\X501\MatchingRule\MatchingRule;
use SpomkyLabs\Pki\X509\Certificate\Extensions;

/**
 * Implements value for 'Extension request' attribute.
 *
 * @see https://tools.ietf.org/html/rfc2985#page-17
 */
final class ExtensionRequestValue extends AttributeValue
{
    final public const OID = '1.2.840.113549.1.9.14';

    /**
     * @param Extensions $_extensions Extensions.
     */
    public function __construct(
        protected Extensions $_extensions
    ) {
        parent::__construct(self::OID);
    }

    /**
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el): AttributeValue
    {
        return new self(Extensions::fromASN1($el->asSequence()));
    }

    /**
     * Get requested extensions.
     */
    public function extensions(): Extensions
    {
        return $this->_extensions;
    }

    public function toASN1(): Element
    {
        return $this->_extensions->toASN1();
    }

    public function stringValue(): string
    {
        return '#' . bin2hex($this->toASN1()->toDER());
    }

    public function equalityMatchingRule(): MatchingRule
    {
        return new BinaryMatch();
    }

    public function rfc2253String(): string
    {
        return $this->stringValue();
    }

    protected function _transcodedString(): string
    {
        return $this->stringValue();
    }
}
