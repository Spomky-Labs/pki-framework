<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Hash;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class RFC4231HMACAITest extends TestCase
{
    /**
     * @test
     */
    public function decodeWithParams()
    {
        $seq = new Sequence(new ObjectIdentifier(AlgorithmIdentifier::OID_HMAC_WITH_SHA256), new NullType());
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(HMACWithSHA256AlgorithmIdentifier::class, $ai);
    }

    /**
     * @test
     */
    public function decodeWithInvalidParamsFail()
    {
        $seq = new Sequence(new ObjectIdentifier(AlgorithmIdentifier::OID_HMAC_WITH_SHA256), new Boolean(true));
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }
}
