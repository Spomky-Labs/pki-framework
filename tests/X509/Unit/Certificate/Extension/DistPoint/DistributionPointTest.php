<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\DistPoint;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\AttributeTypeAndValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\RDN;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\FullName;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\RelativeName;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class DistributionPointTest extends TestCase
{
    #[Test]
    public function createWithFullName(): DistributionPoint
    {
        $dp = DistributionPoint::create(
            FullName::fromURI('urn:test'),
            ReasonFlags::create(ReasonFlags::KEY_COMPROMISE),
            GeneralNames::create(DirectoryName::fromDNString('cn=Issuer'))
        );
        static::assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    #[Test]
    #[Depends('createWithFullName')]
    public function encodeWithFullName(DistributionPoint $dp): string
    {
        $el = $dp->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encodeWithFullName')]
    public function decodeWithFullName($data): DistributionPoint
    {
        $qual = DistributionPoint::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(DistributionPoint::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('createWithFullName')]
    #[Depends('decodeWithFullName')]
    public function recodedWithFullName(DistributionPoint $ref, DistributionPoint $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createWithFullName')]
    public function distributionPointName(DistributionPoint $dp)
    {
        static::assertInstanceOf(DistributionPointName::class, $dp->distributionPointName());
    }

    #[Test]
    #[Depends('createWithFullName')]
    public function fullName(DistributionPoint $dp)
    {
        static::assertInstanceOf(FullName::class, $dp->fullName());
    }

    #[Test]
    #[Depends('createWithFullName')]
    public function relativeNameFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->relativeName();
    }

    #[Test]
    #[Depends('createWithFullName')]
    public function reasons(DistributionPoint $dp)
    {
        static::assertInstanceOf(ReasonFlags::class, $dp->reasons());
    }

    #[Test]
    #[Depends('createWithFullName')]
    public function cRLIssuer(DistributionPoint $dp)
    {
        static::assertInstanceOf(GeneralNames::class, $dp->crlIssuer());
    }

    #[Test]
    public function createWithRelativeName()
    {
        $dp = DistributionPoint::create(
            RelativeName::create(
                RDN::create(AttributeTypeAndValue::fromAttributeValue(CommonNameValue::create('Test')))
            )
        );
        static::assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    #[Test]
    #[Depends('createWithRelativeName')]
    public function encodeWithRelativeName(DistributionPoint $dp)
    {
        $el = $dp->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encodeWithRelativeName')]
    public function decodeWithRelativeName($data)
    {
        $qual = DistributionPoint::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(DistributionPoint::class, $qual);
        return $qual;
    }

    #[Test]
    #[Depends('createWithRelativeName')]
    #[Depends('decodeWithRelativeName')]
    public function recodedWithRelativeName(DistributionPoint $ref, DistributionPoint $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createWithRelativeName')]
    public function relativeName(DistributionPoint $dp)
    {
        static::assertInstanceOf(RelativeName::class, $dp->relativeName());
    }

    #[Test]
    #[Depends('createWithRelativeName')]
    public function fullNameFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->fullName();
    }

    #[Test]
    public function createEmpty()
    {
        $dp = DistributionPoint::create();
        static::assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    #[Test]
    #[Depends('createEmpty')]
    public function distributionPointNameFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->distributionPointName();
    }

    #[Test]
    #[Depends('createEmpty')]
    public function reasonsFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->reasons();
    }

    #[Test]
    #[Depends('createEmpty')]
    public function cRLIssuerFail(DistributionPoint $dp)
    {
        $this->expectException(LogicException::class);
        $dp->crlIssuer();
    }
}
