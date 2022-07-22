<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

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
    /**
     * @test
     */
    public function create()
    {
        $odi = new ObjectDigestInfo(
            ObjectDigestInfo::TYPE_PUBLIC_KEY,
            new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            new BitString(hex2bin('ff'))
        );
        static::assertInstanceOf(ObjectDigestInfo::class, $odi);
        return $odi;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(ObjectDigestInfo $odi)
    {
        $seq = $odi->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $odi = ObjectDigestInfo::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(ObjectDigestInfo::class, $odi);
        return $odi;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(ObjectDigestInfo $ref, ObjectDigestInfo $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @test
     */
    public function decodeWithOtherObjectTypeID()
    {
        $algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
        $seq = Sequence::create(
            new Enumerated(ObjectDigestInfo::TYPE_OTHER_OBJECT_TYPES),
            new ObjectIdentifier('1.3.6.1.3'),
            $algo->toASN1(),
            new BitString('')
        );
        $odi = ObjectDigestInfo::fromASN1($seq);
        static::assertInstanceOf(ObjectDigestInfo::class, $odi);
        return $odi;
    }

    /**
     * @depends decodeWithOtherObjectTypeID
     *
     * @test
     */
    public function encodeWithOtherObjectTypeID(ObjectDigestInfo $odi)
    {
        $seq = $odi->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
    }
}
