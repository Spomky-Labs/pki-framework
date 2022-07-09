<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrSyntax;
use function strval;

/**
 * @internal
 */
final class IetfAttrSyntaxTest extends TestCase
{
    /**
     * @test
     */
    public function createEmpty()
    {
        $val = new GroupAttributeValue();
        $this->assertInstanceOf(IetfAttrSyntax::class, $val);
        return $val;
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function noPolicyAuthorityFail(IetfAttrSyntax $val)
    {
        $this->expectException(LogicException::class);
        $val->policyAuthority();
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function noValuesFirstFail(IetfAttrSyntax $val)
    {
        $this->expectException(LogicException::class);
        $val->first();
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function stringValue(IetfAttrSyntax $val)
    {
        $this->assertIsString($val->stringValue());
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function equalityMatchingRule(IetfAttrSyntax $val)
    {
        $this->assertInstanceOf(MatchingRule::class, $val->equalityMatchingRule());
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function rFC2253String(IetfAttrSyntax $val)
    {
        $this->assertIsString($val->rfc2253String());
    }

    /**
     * @depends createEmpty
     *
     * @test
     */
    public function toStringMethod(IetfAttrSyntax $val)
    {
        $this->assertIsString(strval($val));
    }
}
