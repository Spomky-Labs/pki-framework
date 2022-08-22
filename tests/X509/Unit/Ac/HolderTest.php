<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\AttributeCertificate\ObjectDigestInfo;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class HolderTest extends TestCase
{
    private static $_issuerSerial;

    private static $_subject;

    private static $_odi;

    public static function setUpBeforeClass(): void
    {
        self::$_issuerSerial = IssuerSerial::create(GeneralNames::create(DirectoryName::fromDNString('cn=Test')), '1');
        self::$_subject = GeneralNames::create(DirectoryName::fromDNString('cn=Subject'));
        self::$_odi = ObjectDigestInfo::create(
            ObjectDigestInfo::TYPE_PUBLIC_KEY,
            SHA1WithRSAEncryptionAlgorithmIdentifier::create(),
            BitString::create('')
        );
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuerSerial = null;
        self::$_subject = null;
        self::$_odi = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $holder = Holder::create(self::$_issuerSerial, self::$_subject);
        $holder = $holder->withObjectDigestInfo(self::$_odi);
        static::assertInstanceOf(Holder::class, $holder);
        return $holder;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Holder $holder)
    {
        $seq = $holder->toASN1();
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
        $holder = Holder::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(Holder::class, $holder);
        return $holder;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Holder $ref, Holder $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function baseCertificateID(Holder $holder)
    {
        static::assertEquals(self::$_issuerSerial, $holder->baseCertificateID());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function entityName(Holder $holder)
    {
        static::assertEquals(self::$_subject, $holder->entityName());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function objectDigestInfo(Holder $holder)
    {
        static::assertEquals(self::$_odi, $holder->objectDigestInfo());
    }

    /**
     * @test
     */
    public function withBaseCertificateID()
    {
        $holder = Holder::create();
        $holder = $holder->withBaseCertificateID(self::$_issuerSerial);
        static::assertInstanceOf(Holder::class, $holder);
    }

    /**
     * @test
     */
    public function withEntityName()
    {
        $holder = Holder::create();
        $holder = $holder->withEntityName(self::$_subject);
        static::assertInstanceOf(Holder::class, $holder);
    }

    /**
     * @test
     */
    public function withObjectDigestInfo()
    {
        $holder = Holder::create();
        $holder = $holder->withObjectDigestInfo(self::$_odi);
        static::assertInstanceOf(Holder::class, $holder);
    }

    /**
     * @test
     */
    public function noBaseCertificateIDFail()
    {
        $holder = Holder::create();
        $this->expectException(LogicException::class);
        $holder->baseCertificateID();
    }

    /**
     * @test
     */
    public function noEntityNameFail()
    {
        $holder = Holder::create();
        $this->expectException(LogicException::class);
        $holder->entityName();
    }

    /**
     * @test
     */
    public function noObjectDigestInfoFail()
    {
        $holder = Holder::create();
        $this->expectException(LogicException::class);
        $holder->objectDigestInfo();
    }
}
