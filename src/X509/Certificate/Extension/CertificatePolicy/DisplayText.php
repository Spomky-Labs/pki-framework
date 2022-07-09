<?php

declare(strict_types=1);

namespace Sop\X509\Certificate\Extension\CertificatePolicy;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\BMPString;
use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\Primitive\UTF8String;
use Sop\ASN1\Type\Primitive\VisibleString;
use Sop\ASN1\Type\StringType;
use UnexpectedValueException;

/**
 * Implements *DisplayText* ASN.1 CHOICE type used by 'Certificate Policies' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class DisplayText
{
    /**
     * Text.
     *
     * @var string
     */
    protected $_text;

    /**
     * Element tag.
     *
     * @var int
     */
    protected $_tag;

    /**
     * Constructor.
     */
    public function __construct(string $text, int $tag)
    {
        $this->_text = $text;
        $this->_tag = $tag;
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
        switch ($this->_tag) {
            case Element::TYPE_IA5_STRING:
                return new IA5String($this->_text);
            case Element::TYPE_VISIBLE_STRING:
                return new VisibleString($this->_text);
            case Element::TYPE_BMP_STRING:
                return new BMPString($this->_text);
            case Element::TYPE_UTF8_STRING:
                return new UTF8String($this->_text);
            default:
                throw new UnexpectedValueException('Type ' . Element::tagToName($this->_tag) . ' not supported.');
        }
    }
}
