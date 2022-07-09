<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X501\ASN1\AttributeValue\Feature;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\PrintableString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\DN\DNParser;
use SpomkyLabs\Pki\X501\MatchingRule\CaseIgnoreMatch;
use SpomkyLabs\Pki\X501\MatchingRule\MatchingRule;

/**
 * Base class for attribute values having *PrintableString* syntax.
 */
abstract class PrintableStringValue extends AttributeValue
{
    /**
     * Constructor.
     *
     * @param string $_string String value
     */
    public function __construct(protected string $_string)
    {
    }

    /**
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el): AttributeValue
    {
        return new static($el->asPrintableString()->string());
    }

    public function toASN1(): Element
    {
        return new PrintableString($this->_string);
    }

    public function stringValue(): string
    {
        return $this->_string;
    }

    public function equalityMatchingRule(): MatchingRule
    {
        // default to caseIgnoreMatch
        return new CaseIgnoreMatch(Element::TYPE_PRINTABLE_STRING);
    }

    public function rfc2253String(): string
    {
        return DNParser::escapeString($this->_transcodedString());
    }

    protected function _transcodedString(): string
    {
        // PrintableString maps directly to UTF-8
        return $this->_string;
    }
}
