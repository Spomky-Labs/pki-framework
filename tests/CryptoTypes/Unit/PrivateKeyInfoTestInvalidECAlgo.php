<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit;

use BadMethodCallException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

class PrivateKeyInfoTestInvalidECAlgo extends SpecificAlgorithmIdentifier
{
    public function __construct()
    {
        parent::__construct(self::OID_EC_PUBLIC_KEY);
    }

    public function name(): string
    {
        return '';
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in derived class.');
    }

    protected function paramsASN1(): ?Element
    {
        return null;
    }
}
