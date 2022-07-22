<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\AttributeCertificate\Attribute;

use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\MatchingRule\BinaryMatch;
use SpomkyLabs\Pki\X501\MatchingRule\MatchingRule;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * Implements value for 'Role' attribute.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.4.5
 */
final class RoleAttributeValue extends AttributeValue
{
    /**
     * @param GeneralName $_roleName Role name
     * @param null|GeneralNames $_roleAuthority Issuing authority
     */
    public function __construct(
        protected GeneralName $_roleName,
        protected ?GeneralNames $_roleAuthority = null
    ) {
        $this->_oid = AttributeType::OID_ROLE;
    }

    /**
     * Initialize from a role string.
     *
     * @param string $role_name Role name in URI format
     * @param null|GeneralNames $authority Issuing authority
     */
    public static function fromString(string $role_name, ?GeneralNames $authority = null): self
    {
        return new self(new UniformResourceIdentifier($role_name), $authority);
    }

    /**
     * @return self
     */
    public static function fromASN1(UnspecifiedType $el): AttributeValue
    {
        $seq = $el->asSequence();
        $authority = null;
        if ($seq->hasTagged(0)) {
            $authority = GeneralNames::fromASN1(
                $seq->getTagged(0)
                    ->asImplicit(Element::TYPE_SEQUENCE)
                    ->asSequence()
            );
        }
        $name = GeneralName::fromASN1($seq->getTagged(1)->asExplicit()->asTagged());
        return new self($name, $authority);
    }

    /**
     * Check whether issuing authority is present.
     */
    public function hasRoleAuthority(): bool
    {
        return isset($this->_roleAuthority);
    }

    /**
     * Get issuing authority.
     */
    public function roleAuthority(): GeneralNames
    {
        if (! $this->hasRoleAuthority()) {
            throw new LogicException('roleAuthority not set.');
        }
        return $this->_roleAuthority;
    }

    /**
     * Get role name.
     */
    public function roleName(): GeneralName
    {
        return $this->_roleName;
    }

    public function toASN1(): Element
    {
        $elements = [];
        if (isset($this->_roleAuthority)) {
            $elements[] = new ImplicitlyTaggedType(0, $this->_roleAuthority->toASN1());
        }
        $elements[] = new ExplicitlyTaggedType(1, $this->_roleName->toASN1());
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
