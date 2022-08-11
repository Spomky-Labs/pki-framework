<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BMPString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\IA5String;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\ASN1\Type\Primitive\VisibleString;
use SpomkyLabs\Pki\ASN1\Type\StringType;
use Stringable;
use UnexpectedValueException;

/**
 * Implements *DisplayText* ASN.1 CHOICE type used by 'Certificate Policies' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
final class DisplayText implements Stringable
{
    public function __construct(
        protected string $_text,
        protected int $_tag
    ) {
    }

    public function __toString(): string
    {
        return $this->string();
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(StringType $el): self
    {
        return new self($el->string(), $el->tag());
    }

    /**
     * Initialize from a UTF-8 string.
     */
    public static function fromString(string $str): self
    {
        return new self($str, Element::TYPE_UTF8_STRING);
    }

    /**
     * Get the text.
     */
    public function string(): string
    {
        return $this->_text;
    }

    /**
     * Generate ASN.1 element.
     */
    public function toASN1(): StringType
    {
        return match ($this->_tag) {
            Element::TYPE_IA5_STRING => IA5String::create($this->_text),
            Element::TYPE_VISIBLE_STRING => VisibleString::create($this->_text),
            Element::TYPE_BMP_STRING => BMPString::create($this->_text),
            Element::TYPE_UTF8_STRING => UTF8String::create($this->_text),
            default => throw new UnexpectedValueException('Type ' . Element::tagToName(
                $this->_tag
            ) . ' not supported.'),
        };
    }
}
