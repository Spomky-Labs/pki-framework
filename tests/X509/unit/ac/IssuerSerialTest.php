<?php

declare(strict_types=1);

namespace unit\ac;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\Certificate\UniqueIdentifier;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @group ac
 *
 * @internal
 */
class IssuerSerialTest extends TestCase
{
    private static $_issuer;

    private static $_uid;

    public static function setUpBeforeClass(): void
    {
        self::$_issuer = new GeneralNames(DirectoryName::fromDNString('cn=Test'));
        self::$_uid = new UniqueIdentifier(new BitString(hex2bin('ff')));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuer = null;
        self::$_uid = null;
    }

    public function testCreate()
    {
        $iss_ser = new IssuerSerial(self::$_issuer, 1, self::$_uid);
        $this->assertInstanceOf(IssuerSerial::class, $iss_ser);
        return $iss_ser;
    }

    /**
     * @depends testCreate
     *
     * @param IssuerSerial $iss_ser
     */
    public function testEncode(IssuerSerial $iss_ser)
    {
        $seq = $iss_ser->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $iss_ser = IssuerSerial::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(IssuerSerial::class, $iss_ser);
        return $iss_ser;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param IssuerSerial $ref
     * @param IssuerSerial $new
     */
    public function testRecoded(IssuerSerial $ref, IssuerSerial $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param IssuerSerial $is
     */
    public function testIssuer(IssuerSerial $is)
    {
        $this->assertEquals(self::$_issuer, $is->issuer());
    }

    /**
     * @depends testCreate
     *
     * @param IssuerSerial $is
     */
    public function testSerial(IssuerSerial $is)
    {
        $this->assertEquals(1, $is->serial());
    }

    /**
     * @depends testCreate
     *
     * @param IssuerSerial $is
     */
    public function testIssuerUID(IssuerSerial $is)
    {
        $this->assertEquals(self::$_uid, $is->issuerUID());
    }

    public function testNoIssuerUIDFail()
    {
        $is = new IssuerSerial(self::$_issuer, 1);
        $this->expectException(\LogicException::class);
        $is->issuerUID();
    }
}
