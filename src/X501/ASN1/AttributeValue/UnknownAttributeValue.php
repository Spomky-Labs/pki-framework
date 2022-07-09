<?php

declare(strict_types=1);

namespace Sop\X501\ASN1\AttributeValue;

use BadMethodCallException;
use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\DN\DNParser;
use Sop\X501\MatchingRule\BinaryMatch;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X501\StringPrep\TranscodeStep;

/**
 * Class to hold ASN.1 structure of an unimplemented attribute value.
 */
final class UnknownAttributeValue extends AttributeValue
{
    public function __construct(
        string $oid, /**
     * ASN.1 element.
     */
    protected Element $_element
    ) {
        $this->_oid = $oid;
    }

    public function toASN1(): Element
    {
        return $this->_element;
    }

    public function stringValue(): string
    {
        // if value is encoded as a string type
        if ($this->_element->isType(Element::TYPE_STRING)) {
            return $this->_element->asUnspecified()
                ->asString()
                ->string();
        }
        // return DER encoding as a hexstring (see RFC2253 section 2.4)
        return '#' . bin2hex($this->_element->toDER());
    }

    public function equalityMatchingRule(): MatchingRule
    {
        return new BinaryMatch();
    }

    public function rfc2253String(): string
    {
        $str = $this->_transcodedString();
        // if value has a string representation
        if ($this->_element->isType(Element::TYPE_STRING)) {
            $str = DNParser::escapeString($str);
        }
        return $str;
    }

    protected function _transcodedString(): string
    {
        // if transcoding is defined for the value type
        if (TranscodeStep::isTypeSupported($this->_element->tag())) {
            $step = new TranscodeStep($this->_element->tag());
            return $step->apply($this->stringValue());
        }
        return $this->stringValue();
    }

    public static function fromASN1(UnspecifiedType $el): AttributeValue
    {
        throw new BadMethodCallException('ASN.1 parsing must be implemented in a concrete class.');
    }
}
