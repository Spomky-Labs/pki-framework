<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\Target;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Target;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetGroup;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetName;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Targets;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class TargetsTest extends TestCase
{
    private static $_name;

    private static $_group;

    public static function setUpBeforeClass(): void
    {
        self::$_name = new TargetName(UniformResourceIdentifier::create('urn:target'));
        self::$_group = new TargetGroup(UniformResourceIdentifier::create('urn:group'));
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
        static::assertInstanceOf(Targets::class, $targets);
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
        $targets = Targets::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(Targets::class, $targets);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(Targets $targets)
    {
        static::assertContainsOnlyInstancesOf(Target::class, $targets->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Targets $targets)
    {
        static::assertCount(2, $targets);
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
        static::assertContainsOnlyInstancesOf(Target::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasTarget(Targets $targets)
    {
        static::assertTrue($targets->hasTarget(self::$_name));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function hasNoTarget(Targets $targets)
    {
        static::assertFalse($targets->hasTarget(new TargetName(DNSName::create('nope'))));
    }
}
