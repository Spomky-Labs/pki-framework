<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;

/**
 * Implements 'No Revocation Available' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.3.6
 */
final class NoRevocationAvailableExtension extends Extension
{
    public function __construct(bool $critical)
    {
        parent::__construct(self::OID_NO_REV_AVAIL, $critical);
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        NullType::fromDER($data);
        return new self($critical);
    }

    protected function _valueASN1(): Element
    {
        return new NullType();
    }
}
