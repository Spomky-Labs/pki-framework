<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X509\AttributeCertificate\Attribute\AuthenticationInfoAttributeValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class AuthenticationInfoTest extends TestCase
{
    final public const SERVICE_URI = 'urn:service';

    final public const IDENT_URI = 'urn:username';

    final public const AUTH_INFO = 'password';

    /**
     * @test
     */
    public function create()
    {
        $value = new AuthenticationInfoAttributeValue(
            new UniformResourceIdentifier(self::SERVICE_URI),
            new UniformResourceIdentifier(self::IDENT_URI),
            self::AUTH_INFO
        );
        static::assertInstanceOf(AuthenticationInfoAttributeValue::class, $value);
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
        static::assertInstanceOf(Sequence::class, $el);
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
        $value = AuthenticationInfoAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(AuthenticationInfoAttributeValue::class, $value);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(AttributeValue $value)
    {
        static::assertEquals(AuthenticationInfoAttributeValue::OID, $value->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function service(AuthenticationInfoAttributeValue $value)
    {
        static::assertEquals(self::SERVICE_URI, $value->service());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function ident(AuthenticationInfoAttributeValue $value)
    {
        static::assertEquals(self::IDENT_URI, $value->ident());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function authInfo(AuthenticationInfoAttributeValue $value)
    {
        static::assertEquals(self::AUTH_INFO, $value->authInfo());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        static::assertTrue($attribs->hasAuthenticationInformation());
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function fromAttributes(Attributes $attribs)
    {
        static::assertInstanceOf(AuthenticationInfoAttributeValue::class, $attribs->authenticationInformation());
    }
}
