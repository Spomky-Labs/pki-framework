<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\Target;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\TargetGroup;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\Certificate\Extension\Target\Targets;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class TargetsTest extends TestCase
{
    private static $_name;

    private static $_group;

    public static function setUpBeforeClass(): void
    {
        self::$_name = new TargetName(new UniformResourceIdentifier('urn:target'));
        self::$_group = new TargetGroup(new UniformResourceIdentifier('urn:group'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_name = null;
        self::$_group = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $targets = new Targets(self::$_name, self::$_group);
        $this->assertInstanceOf(Targets::class, $targets);
        return $targets;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Targets $targets)
    {
        $el = $targets->toASN1();
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
        $targets = Targets::fromASN1(Sequence::fromDER($data));
        $this->assertInstanceOf(Targets::class, $targets);
        return $targets;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Targets $ref, Targets $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(Targets $targets)
    {
        $this->assertContainsOnlyInstancesOf(Target::class, $targets->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Targets $targets)
    {
        $this->assertCount(2, $targets);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(Targets $targets)
    {
        $values = [];
        foreach ($targets as $target) {
            $values[] = $target;
        }
        $this->assertContainsOnlyInstancesOf(Target::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasTarget(Targets $targets)
    {
        $this->assertTrue($targets->hasTarget(self::$_name));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNoTarget(Targets $targets)
    {
        $this->assertFalse($targets->hasTarget(new TargetName(new DNSName('nope'))));
    }
}
