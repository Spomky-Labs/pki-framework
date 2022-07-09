<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\AccessDescription;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\AccessDescription\AuthorityAccessDescription;
use Sop\X509\GeneralName\UniformResourceIdentifier;

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
        $this->assertInstanceOf(AuthorityAccessDescription::class, $desc);
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
        $this->assertInstanceOf(Sequence::class, $el);
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
        $this->assertInstanceOf(AuthorityAccessDescription::class, $desc);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function isOSCP(AuthorityAccessDescription $desc)
    {
        $this->assertTrue($desc->isOSCPMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function isNotCAIssuers(AuthorityAccessDescription $desc)
    {
        $this->assertFalse($desc->isCAIssuersMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function accessMethod(AuthorityAccessDescription $desc)
    {
        $this->assertEquals(AuthorityAccessDescription::OID_METHOD_OSCP, $desc->accessMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function location(AuthorityAccessDescription $desc)
    {
        $this->assertEquals(self::URI, $desc->accessLocation() ->string());
    }
}
