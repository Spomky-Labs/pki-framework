<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\Target;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Target;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetGroup;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class TargetGroupTest extends TestCase
{
    final public const URI = 'urn:test';

    #[Test]
    public function create(): TargetGroup
    {
        $target = TargetGroup::create(UniformResourceIdentifier::create(self::URI));
        static::assertInstanceOf(TargetGroup::class, $target);
        return $target;
    }

    #[Test]
    #[Depends('create')]
    public function encode(Target $target): string
    {
        $el = $target->toASN1();
        static::assertInstanceOf(ExplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): TargetGroup
    {
        $target = TargetGroup::fromASN1(TaggedType::fromDER($data));
        static::assertInstanceOf(TargetGroup::class, $target);
        return $target;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Target $ref, Target $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function type(Target $target)
    {
        static::assertSame(Target::TYPE_GROUP, $target->type());
    }

    #[Test]
    #[Depends('create')]
    public function verifyName(?TargetGroup $target = null)
    {
        $name = $target->name();
        static::assertInstanceOf(GeneralName::class, $name);
    }

    #[Test]
    #[Depends('create')]
    public function string(TargetGroup $target)
    {
        static::assertIsString($target->string());
    }
}
