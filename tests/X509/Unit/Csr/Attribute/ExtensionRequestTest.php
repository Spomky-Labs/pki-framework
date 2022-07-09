<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Csr\Attribute;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\Certificate\Extensions;
use Sop\X509\CertificationRequest\Attribute\ExtensionRequestValue;

/**
 * @internal
 */
final class ExtensionRequestTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $value = new ExtensionRequestValue(new Extensions());
        $this->assertInstanceOf(ExtensionRequestValue::class, $value);
        return $value;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(AttributeValue $value)
    {
        $el = $value->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $value = ExtensionRequestValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(ExtensionRequestValue::class, $value);
        return $value;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(AttributeValue $ref, AttributeValue $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(AttributeValue $value)
    {
        $this->assertEquals(ExtensionRequestValue::OID, $value->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(ExtensionRequestValue $value)
    {
        $this->assertInstanceOf(Extensions::class, $value->extensions());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function stringValue(ExtensionRequestValue $value)
    {
        $this->assertIsString($value->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function equalityMatchingRule(ExtensionRequestValue $value)
    {
        $this->assertInstanceOf(MatchingRule::class, $value->equalityMatchingRule());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function rFC2253String(ExtensionRequestValue $value)
    {
        $this->assertIsString($value->rfc2253String());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(ExtensionRequestValue $value)
    {
        $this->assertIsString(strval($value));
    }
}
