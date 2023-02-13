<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Enumerated;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\X509\AttributeCertificate\ObjectDigestInfo;

/**
 * @internal
 */
final class ObjectDigestInfoTest extends TestCase
{
    #[Test]
    public function create(): ObjectDigestInfo
    {
        $odi = ObjectDigestInfo::create(
            ObjectDigestInfo::TYPE_PUBLIC_KEY,
            SHA1WithRSAEncryptionAlgorithmIdentifier::create(),
            BitString::create(hex2bin('ff'))
        );
        static::assertInstanceOf(ObjectDigestInfo::class, $odi);
        return $odi;
    }

    #[Test]
    #[Depends('create')]
    public function encode(ObjectDigestInfo $odi): string
    {
        $seq = $odi->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): ObjectDigestInfo
    {
        $odi = ObjectDigestInfo::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(ObjectDigestInfo::class, $odi);
        return $odi;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(ObjectDigestInfo $ref, ObjectDigestInfo $new): void
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    public function decodeWithOtherObjectTypeID(): ObjectDigestInfo
    {
        $algo = SHA1WithRSAEncryptionAlgorithmIdentifier::create();
        $seq = Sequence::create(
            Enumerated::create(ObjectDigestInfo::TYPE_OTHER_OBJECT_TYPES),
            ObjectIdentifier::create('1.3.6.1.3'),
            $algo->toASN1(),
            BitString::create('')
        );
        $odi = ObjectDigestInfo::fromASN1($seq);
        static::assertInstanceOf(ObjectDigestInfo::class, $odi);
        return $odi;
    }

    #[Test]
    #[Depends('decodeWithOtherObjectTypeID')]
    public function encodeWithOtherObjectTypeID(ObjectDigestInfo $odi): void
    {
        $seq = $odi->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
    }
}
