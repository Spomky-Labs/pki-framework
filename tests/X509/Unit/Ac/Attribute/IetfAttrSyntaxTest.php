<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\TestCase;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrSyntax;

/**
 * @internal
 */
final class IetfAttrSyntaxTest extends TestCase
{
    public function testCreateEmpty()
    {
        $val = new GroupAttributeValue();
        $this->assertInstanceOf(IetfAttrSyntax::class, $val);
        return $val;
    }

    /**
     * @depends testCreateEmpty
     */
    public function testNoPolicyAuthorityFail(IetfAttrSyntax $val)
    {
        $this->expectException(\LogicException::class);
        $val->policyAuthority();
    }

    /**
     * @depends testCreateEmpty
     */
    public function testNoValuesFirstFail(IetfAttrSyntax $val)
    {
        $this->expectException(\LogicException::class);
        $val->first();
    }

    /**
     * @depends testCreateEmpty
     */
    public function testStringValue(IetfAttrSyntax $val)
    {
        $this->assertIsString($val->stringValue());
    }

    /**
     * @depends testCreateEmpty
     */
    public function testEqualityMatchingRule(IetfAttrSyntax $val)
    {
        $this->assertInstanceOf(MatchingRule::class, $val->equalityMatchingRule());
    }

    /**
     * @depends testCreateEmpty
     */
    public function testRFC2253String(IetfAttrSyntax $val)
    {
        $this->assertIsString($val->rfc2253String());
    }

    /**
     * @depends testCreateEmpty
     */
    public function testToString(IetfAttrSyntax $val)
    {
        $this->assertIsString(strval($val));
    }
}
