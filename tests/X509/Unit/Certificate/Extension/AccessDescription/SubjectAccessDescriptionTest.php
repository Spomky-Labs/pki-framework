<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\AccessDescription;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\AccessDescription\SubjectAccessDescription;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class SubjectAccessDescriptionTest extends TestCase
{
    public const URI = 'urn:test';

    /**
     * @test
     */
    public function create()
    {
        $desc = new SubjectAccessDescription(
            SubjectAccessDescription::OID_METHOD_CA_REPOSITORY,
            new UniformResourceIdentifier(self::URI)
        );
        $this->assertInstanceOf(SubjectAccessDescription::class, $desc);
        return $desc;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(SubjectAccessDescription $desc)
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
        $desc = SubjectAccessDescription::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(SubjectAccessDescription::class, $desc);
        return $desc;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(SubjectAccessDescription $ref, SubjectAccessDescription $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function isCARepository(SubjectAccessDescription $desc)
    {
        $this->assertTrue($desc->isCARepositoryMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function isNotTimeStamping(SubjectAccessDescription $desc)
    {
        $this->assertFalse($desc->isTimeStampingMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function accessMethod(SubjectAccessDescription $desc)
    {
        $this->assertEquals(SubjectAccessDescription::OID_METHOD_CA_REPOSITORY, $desc->accessMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function location(SubjectAccessDescription $desc)
    {
        $this->assertEquals(self::URI, $desc->accessLocation() ->string());
    }
}
