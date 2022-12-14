<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePoliciesExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\CPSQualifier;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\NoticeReference;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyQualifierInfo;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\UserNoticeQualifier;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;

/**
 * @internal
 */
final class CertificatePoliciesTest extends RefExtTestHelper
{
    /**
     * @return CertificatePoliciesExtension
     */
    #[Test]
    public function certificatePoliciesExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_CERTIFICATE_POLICIES);
        static::assertInstanceOf(CertificatePoliciesExtension::class, $ext);
        return $ext;
    }

    /**
     * @return PolicyInformation
     */
    #[Test]
    #[Depends('certificatePoliciesExtension')]
    public function policyInformation(CertificatePoliciesExtension $cpe)
    {
        $pi = $cpe->get('1.3.6.1.4.1.45710.2.2.1');
        static::assertInstanceOf(PolicyInformation::class, $pi);
        return $pi;
    }

    /**
     * @return CPSQualifier
     */
    #[Test]
    #[Depends('policyInformation')]
    public function policyCPSQualifier(PolicyInformation $pi)
    {
        $cps = $pi->get(PolicyQualifierInfo::OID_CPS);
        static::assertInstanceOf(CPSQualifier::class, $cps);
        return $cps;
    }

    #[Test]
    #[Depends('policyCPSQualifier')]
    public function policyCPSQualifierURI(CPSQualifier $cps)
    {
        static::assertEquals('http://example.com/cps.html', $cps->uri());
    }

    /**
     * @return UserNoticeQualifier
     */
    #[Test]
    #[Depends('policyInformation')]
    public function policyUserNoticeQualifier(PolicyInformation $pi)
    {
        $un = $pi->get(PolicyQualifierInfo::OID_UNOTICE);
        static::assertInstanceOf(UserNoticeQualifier::class, $un);
        return $un;
    }

    #[Test]
    #[Depends('policyUserNoticeQualifier')]
    public function policyUserNoticeQualifierText(UserNoticeQualifier $un)
    {
        static::assertEquals('All your base are belong to us!', $un->explicitText()->string());
    }

    /**
     * @return NoticeReference
     */
    #[Test]
    #[Depends('policyUserNoticeQualifier')]
    public function policyUserNoticeQualifierRef(UserNoticeQualifier $un)
    {
        $ref = $un->noticeRef();
        static::assertInstanceOf(NoticeReference::class, $ref);
        return $ref;
    }

    #[Test]
    #[Depends('policyUserNoticeQualifierRef')]
    public function policyUserNoticeQualifierOrganization(NoticeReference $ref)
    {
        static::assertEquals('Toaplan Co., Ltd.', $ref->organization()->string());
    }

    #[Test]
    #[Depends('policyUserNoticeQualifierRef')]
    public function policyUserNoticeQualifierNumbers(NoticeReference $ref)
    {
        static::assertEquals([1, 2], $ref->numbers());
    }
}
