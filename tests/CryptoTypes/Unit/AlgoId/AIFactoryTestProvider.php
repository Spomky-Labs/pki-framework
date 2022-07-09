<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId;

use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierProvider;

class AIFactoryTestProvider implements AlgorithmIdentifierProvider
{
    public function supportsOID(string $oid): bool
    {
        return $oid === '1.3.6.1.3';
    }

    public function getClassByOID(string $oid): string
    {
        return AIFactoryTestCustomAlgo::class;
    }
}
