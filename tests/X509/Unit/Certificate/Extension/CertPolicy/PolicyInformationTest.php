<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\CertPolicy;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\DisplayText;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;

/**
 * @internal
 */
final class PolicyInformationTest extends TestCase
{
    public const OID = '1.3.6.1.3';

    #[Test]
    public function createWithCPS(): PolicyInformation
    {
        $pi = PolicyInformation::create(self::OID, CPSQualifier::create('urn:test'));
        static::assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    #[Test]
    #[Depends('createWithCPS')]
    public function encodeWithCPS(PolicyInformation $pi): string
    {
        $el = $pi->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encodeWithCPS')]
    public function decodeWithCPS($data): PolicyInformation
    {
        $pi = PolicyInformation::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    #[Test]
    #[Depends('createWithCPS')]
    #[Depends('decodeWithCPS')]
    public function recodedWithCPS(PolicyInformation $ref, PolicyInformation $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createWithCPS')]
    public function oID(PolicyInformation $pi)
    {
        static::assertSame(self::OID, $pi->oid());
    }

    #[Test]
    #[Depends('createWithCPS')]
    public function has(PolicyInformation $pi)
    {
        static::assertTrue($pi->has(CPSQualifier::OID_CPS));
    }

    #[Test]
    #[Depends('createWithCPS')]
    public function hasNot(PolicyInformation $pi)
    {
        static::assertFalse($pi->has('1.3.6.1.3'));
    }

    #[Test]
    #[Depends('createWithCPS')]
    public function get(PolicyInformation $pi)
    {
        static::assertInstanceOf(PolicyQualifierInfo::class, $pi->get(CPSQualifier::OID_CPS));
    }

    #[Test]
    #[Depends('createWithCPS')]
    public function getFail(PolicyInformation $pi)
    {
        $this->expectException(LogicException::class);
        $pi->get('1.3.6.1.3');
    }

    #[Test]
    #[Depends('createWithCPS')]
    public function cPSQualifier(PolicyInformation $pi)
    {
        static::assertInstanceOf(CPSQualifier::class, $pi->CPSQualifier());
    }

    #[Test]
    #[Depends('createWithCPS')]
    public function userNoticeQualifierFail(PolicyInformation $pi)
    {
        $this->expectException(LogicException::class);
        $pi->userNoticeQualifier();
    }

    #[Test]
    public function createWithNotice()
    {
        $pi = PolicyInformation::create(self::OID, UserNoticeQualifier::create(DisplayText::fromString('notice')));
        static::assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    #[Test]
    #[Depends('createWithNotice')]
    public function cPSQualifierFail(PolicyInformation $pi)
    {
        $this->expectException(LogicException::class);
        $pi->CPSQualifier();
    }

    #[Test]
    #[Depends('createWithNotice')]
    public function userNoticeQualifier(PolicyInformation $pi)
    {
        static::assertInstanceOf(UserNoticeQualifier::class, $pi->userNoticeQualifier());
    }

    #[Test]
    public function createWithMultiple()
    {
        $pi = PolicyInformation::create(
            self::OID,
            CPSQualifier::create('urn:test'),
            UserNoticeQualifier::create(DisplayText::fromString('notice'))
        );
        static::assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    #[Test]
    #[Depends('createWithMultiple')]
    public function encodeWithMultiple(PolicyInformation $pi)
    {
        $el = $pi->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encodeWithMultiple')]
    public function decodeWithMultiple($data)
    {
        $pi = PolicyInformation::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    #[Test]
    #[Depends('createWithMultiple')]
    #[Depends('decodeWithMultiple')]
    public function recodedMultiple(PolicyInformation $ref, PolicyInformation $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createWithMultiple')]
    public function countMethod(PolicyInformation $pi)
    {
        static::assertCount(2, $pi);
    }

    #[Test]
    #[Depends('createWithMultiple')]
    public function iterator(PolicyInformation $pi)
    {
        $values = [];
        foreach ($pi as $qual) {
            $values[] = $qual;
        }
        static::assertContainsOnlyInstancesOf(PolicyQualifierInfo::class, $values);
    }

    #[Test]
    public function isAnyPolicy()
    {
        $pi = PolicyInformation::create(PolicyInformation::OID_ANY_POLICY);
        static::assertTrue($pi->isAnyPolicy());
    }
}
