<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

class AIFactoryTestCustomAlgo extends SpecificAlgorithmIdentifier
{
    private function __construct()
    {
        parent::__construct(self::OID_HMAC_WITH_SHA384);
    }

    public static function create(): self
    {
        return new self();
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        return self::create();
    }

    public function name(): string
    {
        return '';
    }

    protected function paramsASN1(): ?Element
    {
        return null;
    }
}
