<?php

declare(strict_types=1);

namespace unit\ac\attribute;

use PHPUnit\Framework\TestCase;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\SvceAuthInfo;
use Sop\X509\GeneralName\DirectoryName;

/**
 * @group ac
 * @group attribute
 *
 * @internal
 */
class SvceAuthInfoTest extends TestCase
{
    public function testCreateWithoutAuthInfo()
    {
        $val = new AccessIdentityAttributeValue(
            DirectoryName::fromDNString('cn=Svc'),
            DirectoryName::fromDNString('cn=Ident'));
        $this->assertInstanceOf(SvceAuthInfo::class, $val);
        return $val;
    }

    /**
     * @depends testCreateWithoutAuthInfo
     *
     * @param SvceAuthInfo $val
     */
    public function testNoAuthInfoFail(SvceAuthInfo $val)
    {
        $this->expectException(\LogicException::class);
        $val->authInfo();
    }

    /**
     * @depends testCreateWithoutAuthInfo
     *
     * @param SvceAuthInfo $val
     */
    public function testStringValue(SvceAuthInfo $val)
    {
        $this->assertIsString($val->stringValue());
    }

    /**
     * @depends testCreateWithoutAuthInfo
     *
     * @param SvceAuthInfo $val
     */
    public function testEqualityMatchingRule(SvceAuthInfo $val)
    {
        $this->assertInstanceOf(MatchingRule::class,
            $val->equalityMatchingRule());
    }

    /**
     * @depends testCreateWithoutAuthInfo
     *
     * @param SvceAuthInfo $val
     */
    public function testRFC2253String(SvceAuthInfo $val)
    {
        $this->assertIsString($val->rfc2253String());
    }

    /**
     * @depends testCreateWithoutAuthInfo
     *
     * @param SvceAuthInfo $val
     */
    public function testToString(SvceAuthInfo $val)
    {
        $this->assertIsString(strval($val));
    }
}
