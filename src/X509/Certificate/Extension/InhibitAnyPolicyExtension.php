<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements 'Inhibit anyPolicy' extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.14
 */
final class InhibitAnyPolicyExtension extends Extension
{
    public function __construct(
        bool $critical,
        protected int $_skipCerts
    ) {
        parent::__construct(self::OID_INHIBIT_ANY_POLICY, $critical);
    }

    public function skipCerts(): int
    {
        return $this->_skipCerts;
    }

    protected static function _fromDER(string $data, bool $critical): static
    {
        return new self($critical, UnspecifiedType::fromDER($data)->asInteger()->intNumber());
    }

    protected function _valueASN1(): Element
    {
        return new Integer($this->_skipCerts);
    }
}
