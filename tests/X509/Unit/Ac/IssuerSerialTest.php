<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class IssuerSerialTest extends TestCase
{
    private static ?GeneralNames $_issuer = null;

    private static ?UniqueIdentifier $_uid = null;

    public static function setUpBeforeClass(): void
    {
        self::$_issuer = GeneralNames::create(DirectoryName::fromDNString('cn=Test'));
        self::$_uid = UniqueIdentifier::create(BitString::create(hex2bin('ff')));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuer = null;
        self::$_uid = null;
    }

    #[Test]
    public function create(): IssuerSerial
    {
        $iss_ser = IssuerSerial::create(self::$_issuer, '1', self::$_uid);
        static::assertInstanceOf(IssuerSerial::class, $iss_ser);
        return $iss_ser;
    }

    #[Test]
    #[Depends('create')]
    public function encode(IssuerSerial $iss_ser): string
    {
        $seq = $iss_ser->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): IssuerSerial
    {
        $iss_ser = IssuerSerial::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(IssuerSerial::class, $iss_ser);
        return $iss_ser;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(IssuerSerial $ref, IssuerSerial $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function issuer(IssuerSerial $is)
    {
        static::assertEquals(self::$_issuer, $is->issuer());
    }

    #[Test]
    #[Depends('create')]
    public function serial(IssuerSerial $is)
    {
        static::assertSame('1', $is->serial());
    }

    #[Test]
    #[Depends('create')]
    public function issuerUID(IssuerSerial $is)
    {
        static::assertEquals(self::$_uid, $is->issuerUID());
    }

    #[Test]
    public function noIssuerUIDFail()
    {
        $is = IssuerSerial::create(self::$_issuer, '1');
        $this->expectException(LogicException::class);
        $is->issuerUID();
    }
}
