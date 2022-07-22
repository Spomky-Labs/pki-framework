<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\AttributeCertificate\Attribute;

use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\MatchingRule\BinaryMatch;
use SpomkyLabs\Pki\X501\MatchingRule\MatchingRule;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

/**
 * Base class implementing *SvceAuthInfo* ASN.1 type used by attribute certificate attribute values.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.4.1
 */
abstract class SvceAuthInfo extends AttributeValue
{
    public function __construct(
        protected GeneralName $_service,
        protected GeneralName $_ident,
        protected ?string $_authInfo = null
    ) {
    }

    abstract public static function fromASN1(UnspecifiedType $el): static;

    /**
     * Get service name.
     */
    public function service(): GeneralName
    {
        return $this->_service;
    }

    public function ident(): GeneralName
    {
        return $this->_ident;
    }

    /**
     * Check whether authentication info is present.
     */
    public function hasAuthInfo(): bool
    {
        return isset($this->_authInfo);
    }

    /**
     * Get authentication info.
     */
    public function authInfo(): string
    {
        if (! $this->hasAuthInfo()) {
            throw new LogicException('authInfo not set.');
        }
        return $this->_authInfo;
    }

    public function toASN1(): Element
    {
        $elements = [$this->_service->toASN1(), $this->_ident->toASN1()];
        if (isset($this->_authInfo)) {
            $elements[] = new OctetString($this->_authInfo);
        }
        return Sequence::create(...$elements);
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
