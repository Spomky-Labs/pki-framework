<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\TargetGroup;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\Certificate\Extension\Target\Targets;
use Sop\X509\Certificate\Extension\TargetInformationExtension;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\DNSName;

/**
 * @internal
 */
final class TargetInformationTest extends TestCase
{
    final public const NAME_DN = 'cn=Target';

    final public const GROUP_DOMAIN = '.example.com';

    /**
     * @test
     */
    public function createTargets()
    {
        $targets = new Targets(
            new TargetName(DirectoryName::fromDNString(self::NAME_DN)),
            new TargetGroup(new DNSName(self::GROUP_DOMAIN))
        );
        $this->assertInstanceOf(Targets::class, $targets);
        return $targets;
    }

    /**
     * @depends createTargets
     *
     * @test
     */
    public function create(Targets $targets)
    {
        $ext = new TargetInformationExtension(true, $targets);
        $this->assertInstanceOf(TargetInformationExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_TARGET_INFORMATION, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
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
        $ext = TargetInformationExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(TargetInformationExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(TargetInformationExtension $ext)
    {
        $this->assertCount(2, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(TargetInformationExtension $ext)
    {
        $values = [];
        foreach ($ext as $target) {
            $values[] = $target;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(Target::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function name(TargetInformationExtension $ext)
    {
        $this->assertEquals(self::NAME_DN, $ext->names()[0]->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function group(TargetInformationExtension $ext)
    {
        $this->assertEquals(self::GROUP_DOMAIN, $ext->groups()[0]->string());
    }

    /**
     * Cover __clone method.
     *
     * @depends create
     *
     * @test
     */
    public function clone(TargetInformationExtension $ext)
    {
        $this->assertInstanceOf(TargetInformationExtension::class, clone $ext);
    }

    /**
     * @test
     */
    public function fromTargets()
    {
        $ext = TargetInformationExtension::fromTargets(new TargetName(DirectoryName::fromDNString(self::NAME_DN)));
        $this->assertInstanceOf(TargetInformationExtension::class, $ext);
    }
}
