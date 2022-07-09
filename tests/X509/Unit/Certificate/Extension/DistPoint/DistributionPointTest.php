<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\DistPoint;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeTypeAndValue;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\RDN;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use Sop\X509\Certificate\Extension\DistributionPoint\FullName;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use Sop\X509\Certificate\Extension\DistributionPoint\RelativeName;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class DistributionPointTest extends TestCase
{
    /**
     * @test
     */
    public function createWithFullName()
    {
        $dp = new DistributionPoint(
            FullName::fromURI('urn:test'),
            new ReasonFlags(ReasonFlags::KEY_COMPROMISE),
            new GeneralNames(DirectoryName::fromDNString('cn=Issuer'))
        );
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    /**
     * @depends createWithFullName
     *
     * @test
     */
    public function encodeWithFullName(DistributionPoint $dp)
    {
        $el = $dp->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encodeWithFullName
     *
     * @param string $data
     *
     * @test
     */
    public function decodeWithFullName($data)
    {
        $qual = DistributionPoint::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(DistributionPoint::class, $qual);
        return $qual;
    }

    /**
     * @depends createWithFullName
     * @depends decodeWithFullName
     *
     * @test
     */
    public function recodedWithFullName(DistributionPoint $ref, DistributionPoint $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends createWithFullName
     *
     * @test
     */
    public function distributionPointName(DistributionPoint $dp)
    {
        $this->assertInstanceOf(DistributionPointName::class, $dp->distributionPointName());
    }

    /**
     * @depends createWithFullName
     *
     * @test
     */
    public function fullName(DistributionPoint $dp)
    {
        $this->assertInstanceOf(FullName::class, $dp->fullName());
    }

    /**
     * @depends createWithFullName
     *
     * @test
     */
    public function relativeNameFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->relativeName();
    }

    /**
     * @depends createWithFullName
     *
     * @test
     */
    public function reasons(DistributionPoint $dp)
    {
        $this->assertInstanceOf(ReasonFlags::class, $dp->reasons());
    }

    /**
     * @depends createWithFullName
     *
     * @test
     */
    public function cRLIssuer(DistributionPoint $dp)
    {
        $this->assertInstanceOf(GeneralNames::class, $dp->crlIssuer());
    }

    /**
     * @test
     */
    public function createWithRelativeName()
    {
        $dp = new DistributionPoint(
            new RelativeName(new RDN(AttributeTypeAndValue::fromAttributeValue(new CommonNameValue('Test'))))
        );
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    /**
     * @depends createWithRelativeName
     *
     * @test
     */
    public function encodeWithRelativeName(DistributionPoint $dp)
    {
        $el = $dp->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encodeWithRelativeName
     *
     * @param string $data
     *
     * @test
     */
    public function decodeWithRelativeName($data)
    {
        $qual = DistributionPoint::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(DistributionPoint::class, $qual);
        return $qual;
    }

    /**
     * @depends createWithRelativeName
     * @depends decodeWithRelativeName
     *
     * @test
     */
    public function recodedWithRelativeName(DistributionPoint $ref, DistributionPoint $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends createWithRelativeName
     *
     * @test
     */
    public function relativeName(DistributionPoint $dp)
    {
        $this->assertInstanceOf(RelativeName::class, $dp->relativeName());
    }

    /**
     * @depends createWithRelativeName
     *
     * @test
     */
    public function fullNameFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->fullName();
    }

    /**
     * @test
     */
    public function createEmpty()
    {
        $dp = new DistributionPoint();
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function distributionPointNameFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->distributionPointName();
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function reasonsFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->reasons();
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function cRLIssuerFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->crlIssuer();
    }
}
