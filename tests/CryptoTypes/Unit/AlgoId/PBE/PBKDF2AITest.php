<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\PBE;

use const PHP_INT_MAX;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA1AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA512AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class PBKDF2AITest extends TestCase
{
    private const SALT = '0123456789abcdef';

    #[Test]
    public function defaultsAreOmittedInDER(): void
    {
        $ai = PBKDF2AlgorithmIdentifier::create(self::SALT, 2048);
        static::assertSame(AlgorithmIdentifier::OID_PBKDF2, $ai->oid());
        static::assertSame('PBKDF2', $ai->name());
        static::assertSame(self::SALT, $ai->salt());
        static::assertSame(2048, $ai->iterationCount());
        static::assertNull($ai->keyLength());
        static::assertInstanceOf(HMACWithSHA1AlgorithmIdentifier::class, $ai->prf());
        static::assertEquals(
            Sequence::create(
                ObjectIdentifier::create(AlgorithmIdentifier::OID_PBKDF2),
                Sequence::create(OctetString::create(self::SALT), Integer::create(2048))
            ),
            $ai->toASN1()
        );
    }

    #[Test]
    public function anExplicitHmacWithSHA1IsOmittedInDER(): void
    {
        $ai = PBKDF2AlgorithmIdentifier::create(self::SALT, 1, null, HMACWithSHA1AlgorithmIdentifier::create());
        static::assertCount(2, $ai->toASN1()->at(1)->asSequence());
    }

    #[Test]
    public function everythingIsEncoded(): void
    {
        $prf = HMACWithSHA512AlgorithmIdentifier::create(NullType::create());
        $ai = PBKDF2AlgorithmIdentifier::create(self::SALT, 1000, 32, $prf);
        $expected = Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_PBKDF2),
            Sequence::create(OctetString::create(self::SALT), Integer::create(1000), Integer::create(32), $prf->toASN1())
        );
        static::assertEquals($expected, $ai->toASN1());
        $decoded = AlgorithmIdentifier::fromASN1($expected);
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $decoded);
        static::assertSame(32, $decoded->keyLength());
        static::assertSame(1000, $decoded->iterationCount());
        static::assertInstanceOf(HMACWithSHA512AlgorithmIdentifier::class, $decoded->prf());
        static::assertSame($expected->toDER(), $decoded->toASN1()->toDER());
    }

    #[Test]
    public function keyLengthWithoutPrf(): void
    {
        $ai = PBKDF2AlgorithmIdentifier::create(self::SALT, 5, 16);
        $decoded = AlgorithmIdentifier::fromASN1($ai->toASN1());
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $decoded);
        static::assertSame(16, $decoded->keyLength());
        static::assertSame(5, $decoded->iterationCount());
        static::assertInstanceOf(HMACWithSHA1AlgorithmIdentifier::class, $decoded->prf());
    }

    /**
     * @return iterable<string, array{Sequence}>
     */
    public static function hmacWithSHA1Forms(): iterable
    {
        $oid = ObjectIdentifier::create(AlgorithmIdentifier::OID_HMAC_WITH_SHA1);
        yield 'NULL parameters, as RFC 8018 gives them' => [Sequence::create($oid, NullType::create())];
        yield 'no parameters' => [Sequence::create($oid)];
    }

    #[Test]
    #[DataProvider('hmacWithSHA1Forms')]
    public function anExplicitHmacWithSHA1IsDecoded(Sequence $prf): void
    {
        $decoded = AlgorithmIdentifier::fromASN1(Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_PBKDF2),
            Sequence::create(OctetString::create(self::SALT), Integer::create(1), $prf)
        ));
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $decoded);
        static::assertInstanceOf(HMACWithSHA1AlgorithmIdentifier::class, $decoded->prf());
        // DER omits the default
        static::assertCount(2, $decoded->toASN1()->at(1)->asSequence());
    }

    /**
     * @return iterable<string, array{null|Sequence, string}>
     */
    public static function invalidParams(): iterable
    {
        $salt = OctetString::create(self::SALT);
        yield 'no parameters' => [null, 'No parameters.'];
        yield 'salt from otherSource' => [
            Sequence::create(Sequence::create(ObjectIdentifier::create('1.2.3')), Integer::create(1)),
            'PBKDF2 salt from an otherSource algorithm is not supported.',
        ];
        yield 'iteration count 0' => [
            Sequence::create($salt, Integer::create(0)),
            'PBKDF2 iteration count 0 is out of range.',
        ];
        yield 'negative iteration count' => [
            Sequence::create($salt, Integer::create(-1)),
            'PBKDF2 iteration count -1 is out of range.',
        ];
        yield 'iteration count above PHP_INT_MAX' => [
            Sequence::create($salt, Integer::create('9223372036854775808')),
            'PBKDF2 iteration count 9223372036854775808 is out of range.',
        ];
        yield 'key length 0' => [
            Sequence::create($salt, Integer::create(1), Integer::create(0)),
            'PBKDF2 key length 0 is out of range.',
        ];
        yield 'trailing element' => [
            Sequence::create($salt, Integer::create(1), Integer::create(16), Sequence::create(
                ObjectIdentifier::create(AlgorithmIdentifier::OID_HMAC_WITH_SHA256)
            ), NullType::create()),
            'Unexpected element in PBKDF2 parameters.',
        ];
        yield 'unexpected type after the iteration count' => [
            Sequence::create($salt, Integer::create(1), UTF8String::create('x')),
            'Unexpected element in PBKDF2 parameters.',
        ];
        yield 'hmacWithSHA1 with parameters other than NULL' => [
            Sequence::create($salt, Integer::create(1), Sequence::create(
                ObjectIdentifier::create(AlgorithmIdentifier::OID_HMAC_WITH_SHA1),
                Integer::create(0)
            )),
            'Parameters of hmacWithSHA1 must be NULL or omitted.',
        ];
    }

    #[Test]
    #[DataProvider('invalidParams')]
    public function invalidParamsAreRefused(?Sequence $params, string $message): void
    {
        $elements = [ObjectIdentifier::create(AlgorithmIdentifier::OID_PBKDF2)];
        if ($params !== null) {
            $elements[] = $params;
        }
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage($message);
        AlgorithmIdentifier::fromASN1(Sequence::create(...$elements));
    }

    #[Test]
    public function theLargestIterationCountIsDecoded(): void
    {
        $decoded = AlgorithmIdentifier::fromASN1(Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_PBKDF2),
            Sequence::create(OctetString::create(self::SALT), Integer::create(PHP_INT_MAX))
        ));
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $decoded);
        static::assertSame(PHP_INT_MAX, $decoded->iterationCount());
    }

    /**
     * @return iterable<string, array{int, null|int, string}>
     */
    public static function invalidCreate(): iterable
    {
        yield 'iteration count 0' => [0, null, 'PBKDF2 iteration count must be positive.'];
        yield 'key length 0' => [1, 0, 'PBKDF2 key length must be positive.'];
    }

    #[Test]
    #[DataProvider('invalidCreate')]
    public function createRefusesInvalidValues(int $iterationCount, ?int $keyLength, string $message): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage($message);
        PBKDF2AlgorithmIdentifier::create(self::SALT, $iterationCount, $keyLength);
    }

    #[Test]
    public function createAcceptsTheSmallestValues(): void
    {
        $ai = PBKDF2AlgorithmIdentifier::create('', 1, 1);
        static::assertSame(1, $ai->iterationCount());
        static::assertSame(1, $ai->keyLength());
    }

    #[Test]
    public function anUnknownPrfIsKept(): void
    {
        $prf = Sequence::create(ObjectIdentifier::create('1.2.643.7.1.1.4.2'), NullType::create());
        $decoded = AlgorithmIdentifier::fromASN1(Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_PBKDF2),
            Sequence::create(OctetString::create(self::SALT), Integer::create(1), $prf)
        ));
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $decoded);
        static::assertSame('1.2.643.7.1.1.4.2', $decoded->prf()->oid());
        static::assertSame(Element::TYPE_SEQUENCE, $decoded->toASN1()->at(1)->asSequence()->at(2)->tag());
    }
}
