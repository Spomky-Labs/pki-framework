<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\MatchingRule\MatchingRule;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\IetfAttrSyntax;
use function strval;

/**
 * @internal
 */
final class IetfAttrSyntaxTest extends TestCase
{
    #[Test]
    public function createEmpty(): GroupAttributeValue
    {
        $val = GroupAttributeValue::create();
        static::assertInstanceOf(IetfAttrSyntax::class, $val);
        return $val;
    }

    #[Test]
    #[Depends('createEmpty')]
    public function noPolicyAuthorityFail(IetfAttrSyntax $val)
    {
        $this->expectException(LogicException::class);
        $val->policyAuthority();
    }

    #[Test]
    #[Depends('createEmpty')]
    public function noValuesFirstFail(IetfAttrSyntax $val)
    {
        $this->expectException(LogicException::class);
        $val->first();
    }

    #[Test]
    #[Depends('createEmpty')]
    public function stringValue(IetfAttrSyntax $val)
    {
        static::assertIsString($val->stringValue());
    }

    #[Test]
    #[Depends('createEmpty')]
    public function equalityMatchingRule(IetfAttrSyntax $val)
    {
        static::assertInstanceOf(MatchingRule::class, $val->equalityMatchingRule());
    }

    #[Test]
    #[Depends('createEmpty')]
    public function rFC2253String(IetfAttrSyntax $val)
    {
        static::assertIsString($val->rfc2253String());
    }

    #[Test]
    #[Depends('createEmpty')]
    public function toStringMethod(IetfAttrSyntax $val)
    {
        static::assertIsString(strval($val));
    }
}
