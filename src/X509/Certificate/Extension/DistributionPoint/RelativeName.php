<?php

declare(strict_types=1);

namespace Sop\X509\Certificate\Extension\DistributionPoint;

use Sop\ASN1\Element;
use Sop\X501\ASN1\RDN;

/**
 * Implements 'nameRelativeToCRLIssuer' ASN.1 CHOICE type of *DistributionPointName* used by 'CRL Distribution Points'
 * certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
class RelativeName extends DistributionPointName
{
    public function __construct(/**
     * Relative distinguished name.
     */
    protected RDN $_rdn
    ) {
        $this->_tag = self::TAG_RDN;
    }

    public function rdn(): RDN
    {
        return $this->_rdn;
    }

    protected function _valueASN1(): Element
    {
        return $this->_rdn->toASN1();
    }
}
