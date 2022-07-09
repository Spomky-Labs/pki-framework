<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\X509\AttributeCertificate\Holder;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\AttributeCertificate\ObjectDigestInfo;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

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
        self::$_issuerSerial = new IssuerSerial(new GeneralNames(DirectoryName::fromDNString('cn=Test')), 1);
        self::$_subject = new GeneralNames(DirectoryName::fromDNString('cn=Subject'));
        self::$_odi = new ObjectDigestInfo(
            ObjectDigestInfo::TYPE_PUBLIC_KEY,
            new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            new BitString('')
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
        $holder = new Holder(self::$_issuerSerial, self::$_subject);
        $holder = $holder->withObjectDigestInfo(self::$_odi);
        $this->assertInstanceOf(Holder::class, $holder);
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
        $this->assertInstanceOf(Sequence::class, $seq);
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
        $this->assertInstanceOf(Holder::class, $holder);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function baseCertificateID(Holder $holder)
    {
        $this->assertEquals(self::$_issuerSerial, $holder->baseCertificateID());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function entityName(Holder $holder)
    {
        $this->assertEquals(self::$_subject, $holder->entityName());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function objectDigestInfo(Holder $holder)
    {
        $this->assertEquals(self::$_odi, $holder->objectDigestInfo());
    }

    /**
     * @test
     */
    public function withBaseCertificateID()
    {
        $holder = new Holder();
        $holder = $holder->withBaseCertificateID(self::$_issuerSerial);
        $this->assertInstanceOf(Holder::class, $holder);
    }

    /**
     * @test
     */
    public function withEntityName()
    {
        $holder = new Holder();
        $holder = $holder->withEntityName(self::$_subject);
        $this->assertInstanceOf(Holder::class, $holder);
    }

    /**
     * @test
     */
    public function withObjectDigestInfo()
    {
        $holder = new Holder();
        $holder = $holder->withObjectDigestInfo(self::$_odi);
        $this->assertInstanceOf(Holder::class, $holder);
    }

    /**
     * @test
     */
    public function noBaseCertificateIDFail()
    {
        $holder = new Holder();
        $this->expectException(LogicException::class);
        $holder->baseCertificateID();
    }

    /**
     * @test
     */
    public function noEntityNameFail()
    {
        $holder = new Holder();
        $this->expectException(LogicException::class);
        $holder->entityName();
    }

    /**
     * @test
     */
    public function noObjectDigestInfoFail()
    {
        $holder = new Holder();
        $this->expectException(LogicException::class);
        $holder->objectDigestInfo();
    }
}
