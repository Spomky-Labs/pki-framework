<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\PBE;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES128CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class PBES2AITest extends TestCase
{
    #[Test]
    public function encodeAndDecode(): void
    {
        $kdf = PBKDF2AlgorithmIdentifier::create('saltsalt', 2048);
        $cipher = AES128CBCAlgorithmIdentifier::create('0123456789abcdef');
        $ai = PBES2AlgorithmIdentifier::create($kdf, $cipher);
        static::assertSame(AlgorithmIdentifier::OID_PBES2, $ai->oid());
        static::assertSame('PBES2', $ai->name());
        static::assertSame($kdf, $ai->keyDerivationFunc());
        static::assertSame($cipher, $ai->encryptionScheme());
        $expected = Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_PBES2),
            Sequence::create($kdf->toASN1(), $cipher->toASN1())
        );
        static::assertEquals($expected, $ai->toASN1());
        $decoded = AlgorithmIdentifier::fromASN1($expected);
        static::assertInstanceOf(PBES2AlgorithmIdentifier::class, $decoded);
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $decoded->keyDerivationFunc());
        static::assertInstanceOf(AES128CBCAlgorithmIdentifier::class, $decoded->encryptionScheme());
        static::assertSame($expected->toDER(), $decoded->toASN1()->toDER());
    }

    #[Test]
    public function unknownComponentsAreKept(): void
    {
        // scrypt (RFC 7914) and AES-256-GCM: not supported for decryption, but still a valid structure
        $seq = Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_PBES2),
            Sequence::create(
                Sequence::create(ObjectIdentifier::create('1.3.6.1.4.1.11591.4.11')),
                Sequence::create(ObjectIdentifier::create('2.16.840.1.101.3.4.1.46'))
            )
        );
        $decoded = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(PBES2AlgorithmIdentifier::class, $decoded);
        static::assertInstanceOf(GenericAlgorithmIdentifier::class, $decoded->keyDerivationFunc());
        static::assertInstanceOf(GenericAlgorithmIdentifier::class, $decoded->encryptionScheme());
        static::assertSame($seq->toDER(), $decoded->toASN1()->toDER());
    }

    #[Test]
    public function noParameters(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('No parameters.');
        AlgorithmIdentifier::fromASN1(Sequence::create(ObjectIdentifier::create(AlgorithmIdentifier::OID_PBES2)));
    }

    #[Test]
    public function oneComponent(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('PBES2 parameters must have exactly two elements.');
        AlgorithmIdentifier::fromASN1(Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_PBES2),
            Sequence::create(PBKDF2AlgorithmIdentifier::create('saltsalt', 1)->toASN1())
        ));
    }

    #[Test]
    public function threeComponents(): void
    {
        $kdf = PBKDF2AlgorithmIdentifier::create('saltsalt', 1)->toASN1();
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('PBES2 parameters must have exactly two elements.');
        AlgorithmIdentifier::fromASN1(Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_PBES2),
            Sequence::create($kdf, $kdf, $kdf)
        ));
    }
}
