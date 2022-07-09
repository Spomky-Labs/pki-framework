<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\SvceAuthInfo;
use Sop\X509\GeneralName\DirectoryName;
use function strval;

/**
 * @internal
 */
final class SvceAuthInfoTest extends TestCase
{
    /**
     * @test
     */
    public function createWithoutAuthInfo()
    {
        $val = new AccessIdentityAttributeValue(
            DirectoryName::fromDNString('cn=Svc'),
            DirectoryName::fromDNString('cn=Ident')
        );
        $this->assertInstanceOf(SvceAuthInfo::class, $val);
        return $val;
    }

    /**
     * @depends createWithoutAuthInfo
     *
     * @test
     */
    public function noAuthInfoFail(SvceAuthInfo $val)
    {
        $this->expectException(LogicException::class);
        $val->authInfo();
    }

    /**
     * @depends createWithoutAuthInfo
     *
     * @test
     */
    public function stringValue(SvceAuthInfo $val)
    {
        $this->assertIsString($val->stringValue());
    }

    /**
     * @depends createWithoutAuthInfo
     *
     * @test
     */
    public function equalityMatchingRule(SvceAuthInfo $val)
    {
        $this->assertInstanceOf(MatchingRule::class, $val->equalityMatchingRule());
    }

    /**
     * @depends createWithoutAuthInfo
     *
     * @test
     */
    public function rFC2253String(SvceAuthInfo $val)
    {
        $this->assertIsString($val->rfc2253String());
    }

    /**
     * @depends createWithoutAuthInfo
     *
     * @test
     */
    public function toStringMethod(SvceAuthInfo $val)
    {
        $this->assertIsString(strval($val));
    }
}
