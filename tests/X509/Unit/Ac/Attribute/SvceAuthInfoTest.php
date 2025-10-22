<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\MatchingRule\MatchingRule;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\SvceAuthInfo;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use function strval;

/**
 * @internal
 */
final class SvceAuthInfoTest extends TestCase
{
    #[Test]
    public function createWithoutAuthInfo(): AccessIdentityAttributeValue
    {
        $val = AccessIdentityAttributeValue::create(
            DirectoryName::fromDNString('cn=Svc'),
            DirectoryName::fromDNString('cn=Ident')
        );
        static::assertInstanceOf(SvceAuthInfo::class, $val);
        return $val;
    }

    #[Test]
    #[Depends('createWithoutAuthInfo')]
    public function noAuthInfoFail(SvceAuthInfo $val)
    {
        $this->expectException(LogicException::class);
        $val->authInfo();
    }

    #[Test]
    #[Depends('createWithoutAuthInfo')]
    public function stringValue(SvceAuthInfo $val)
    {
        static::assertIsString($val->stringValue());
    }

    #[Test]
    #[Depends('createWithoutAuthInfo')]
    public function equalityMatchingRule(SvceAuthInfo $val)
    {
        static::assertInstanceOf(MatchingRule::class, $val->equalityMatchingRule());
    }

    #[Test]
    #[Depends('createWithoutAuthInfo')]
    public function rFC2253String(SvceAuthInfo $val)
    {
        static::assertIsString($val->rfc2253String());
    }

    #[Test]
    #[Depends('createWithoutAuthInfo')]
    public function toStringMethod(SvceAuthInfo $val)
    {
        static::assertIsString(strval($val));
    }
}
