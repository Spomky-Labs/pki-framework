<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\AccessDescription;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\AccessDescription\AuthorityAccessDescription;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class AuthorityAccessDescriptionTest extends TestCase
{
    public const URI = 'urn:test';

    /**
     * @test
     */
    public function create()
    {
        $desc = new AuthorityAccessDescription(
            AuthorityAccessDescription::OID_METHOD_OSCP,
            new UniformResourceIdentifier(self::URI)
        );
        static::assertInstanceOf(AuthorityAccessDescription::class, $desc);
        return $desc;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(AuthorityAccessDescription $desc)
    {
        $el = $desc->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $desc = AuthorityAccessDescription::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(AuthorityAccessDescription::class, $desc);
        return $desc;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(AuthorityAccessDescription $ref, AuthorityAccessDescription $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function isOSCP(AuthorityAccessDescription $desc)
    {
        static::assertTrue($desc->isOSCPMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function isNotCAIssuers(AuthorityAccessDescription $desc)
    {
        static::assertFalse($desc->isCAIssuersMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function accessMethod(AuthorityAccessDescription $desc)
    {
        static::assertEquals(AuthorityAccessDescription::OID_METHOD_OSCP, $desc->accessMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function location(AuthorityAccessDescription $desc)
    {
        static::assertEquals(self::URI, $desc->accessLocation()->string());
    }
}
