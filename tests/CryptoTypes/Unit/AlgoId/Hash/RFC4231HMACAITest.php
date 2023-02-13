<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Hash;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class RFC4231HMACAITest extends TestCase
{
    #[Test]
    public function decodeWithParams()
    {
        $seq = Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_HMAC_WITH_SHA256),
            NullType::create()
        );
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(HMACWithSHA256AlgorithmIdentifier::class, $ai);
    }

    #[Test]
    public function decodeWithInvalidParamsFail()
    {
        $seq = Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_HMAC_WITH_SHA256),
            Boolean::create(true)
        );
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }
}
