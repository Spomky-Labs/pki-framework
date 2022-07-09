<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class AccessIdentityTest extends TestCase
{
    final public const SERVICE_URI = 'urn:service';

    final public const IDENT_URI = 'urn:username';

    /**
     * @test
     */
    public function create()
    {
        $value = new AccessIdentityAttributeValue(
            new UniformResourceIdentifier(self::SERVICE_URI),
            new UniformResourceIdentifier(self::IDENT_URI)
        );
        $this->assertInstanceOf(AccessIdentityAttributeValue::class, $value);
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
        $value = AccessIdentityAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(AccessIdentityAttributeValue::class, $value);
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
        $this->assertEquals(AccessIdentityAttributeValue::OID, $value->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function service(AccessIdentityAttributeValue $value)
    {
        $this->assertEquals(self::SERVICE_URI, $value->service());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function ident(AccessIdentityAttributeValue $value)
    {
        $this->assertEquals(self::IDENT_URI, $value->ident());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasAccessIdentity());
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function fromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(AccessIdentityAttributeValue::class, $attribs->accessIdentity());
    }
}
