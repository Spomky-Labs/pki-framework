<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\IA5String;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements *CPSuri* ASN.1 type used by 'Certificate Policies' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
final class CPSQualifier extends PolicyQualifierInfo
{
    public function __construct(
        protected string $_uri
    ) {
        $this->_oid = self::OID_CPS;
    }

    /**
     * @return self
     */
    public static function fromQualifierASN1(UnspecifiedType $el): PolicyQualifierInfo
    {
        return new self($el->asString()->string());
    }

    public function uri(): string
    {
        return $this->_uri;
    }

    protected function _qualifierASN1(): Element
    {
        return new IA5String($this->_uri);
    }
}
