<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId;

use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

class AIFactoryTestCustomAlgo extends SpecificAlgorithmIdentifier
{
    public static function fromASN1Params(
        ?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        return new self();
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
