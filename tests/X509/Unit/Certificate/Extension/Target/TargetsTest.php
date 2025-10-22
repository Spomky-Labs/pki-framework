<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\Target;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    private static ?TargetName $_name = null;

    private static ?TargetGroup $_group = null;

    public static function setUpBeforeClass(): void
    {
        self::$_name = TargetName::create(UniformResourceIdentifier::create('urn:target'));
        self::$_group = TargetGroup::create(UniformResourceIdentifier::create('urn:group'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_name = null;
        self::$_group = null;
    }

    #[Test]
    public function create(): Targets
    {
        $targets = Targets::create(self::$_name, self::$_group);
        static::assertInstanceOf(Targets::class, $targets);
        return $targets;
    }

    #[Test]
    #[Depends('create')]
    public function encode(Targets $targets): string
    {
        $el = $targets->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): Targets
    {
        $targets = Targets::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(Targets::class, $targets);
        return $targets;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Targets $ref, Targets $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function all(Targets $targets)
    {
        static::assertContainsOnlyInstancesOf(Target::class, $targets->all());
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(Targets $targets)
    {
        static::assertCount(2, $targets);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(Targets $targets)
    {
        $values = [];
        foreach ($targets as $target) {
            $values[] = $target;
        }
        static::assertContainsOnlyInstancesOf(Target::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function hasTarget(Targets $targets)
    {
        static::assertTrue($targets->hasTarget(self::$_name));
    }

    #[Test]
    #[Depends('create')]
    public function hasNoTarget(Targets $targets)
    {
        static::assertFalse($targets->hasTarget(TargetName::create(DNSName::create('nope'))));
    }
}
