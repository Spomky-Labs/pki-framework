<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit;

use BadMethodCallException;
use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
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

    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in derived class.');
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}
