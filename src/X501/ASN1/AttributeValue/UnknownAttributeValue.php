<?php

declare(strict_types = 1);

namespace Sop\X501\ASN1\AttributeValue;

use Sop\ASN1\Element;
use Sop\X501\DN\DNParser;
use Sop\X501\MatchingRule\BinaryMatch;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X501\StringPrep\TranscodeStep;

/**
 * Class to hold ASN.1 structure of an unimplemented attribute value.
 */
class UnknownAttributeValue extends AttributeValue
{
    /**
     * ASN.1 element.
     *
     * @var Element
     */
    protected $_element;

    /**
     * Constructor.
     *
     * @param string  $oid
     * @param Element $el
     */
    public function __construct(string $oid, Element $el)
    {
        $this->_oid = $oid;
        $this->_element = $el;
    }

    /**
     * {@inheritdoc}
     */
    public function toASN1(): Element
    {
        return $this->_element;
    }

    /**
     * {@inheritdoc}
     */
    public function stringValue(): string
    {
        // if value is encoded as a string type
        if ($this->_element->isType(Element::TYPE_STRING)) {
            return $this->_element->asUnspecified()->asString()->string();
        }
        // return DER encoding as a hexstring (see RFC2253 section 2.4)
        return '#' . bin2hex($this->_element->toDER());
    }

    /**
     * {@inheritdoc}
     */
    public function equalityMatchingRule(): MatchingRule
    {
        return new BinaryMatch();
    }

    /**
     * {@inheritdoc}
     */
    public function rfc2253String(): string
    {
        $str = $this->_transcodedString();
        // if value has a string representation
        if ($this->_element->isType(Element::TYPE_STRING)) {
            $str = DNParser::escapeString($str);
        }
        return $str;
    }

    /**
     * {@inheritdoc}
     */
    protected function _transcodedString(): string
    {
        // if transcoding is defined for the value type
        if (TranscodeStep::isTypeSupported($this->_element->tag())) {
            $step = new TranscodeStep($this->_element->tag());
            return $step->apply($this->stringValue());
        }
        return $this->stringValue();
    }
}
