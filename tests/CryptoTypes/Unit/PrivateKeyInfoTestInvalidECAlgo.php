<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit;

use Sop\ASN1\Element;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

class PrivateKeyInfoTestInvalidECAlgo extends SpecificAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_EC_PUBLIC_KEY;
    }

    public function name(): string
    {
        return '';
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}
