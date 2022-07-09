<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension\Target;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Tagged\ExplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\Target\TargetName;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class TargetNameTest extends TestCase
{
    final public const URI = 'urn:test';

    /**
     * @test
     */
    public function create()
    {
        $target = new TargetName(new UniformResourceIdentifier(self::URI));
        static::assertInstanceOf(TargetName::class, $target);
        return $target;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Target $target)
    {
        $el = $target->toASN1();
        static::assertInstanceOf(ExplicitTagging::class, $el);
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
        $target = TargetName::fromASN1(TaggedType::fromDER($data));
        static::assertInstanceOf(TargetName::class, $target);
        return $target;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Target $ref, Target $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function type(Target $target)
    {
        static::assertEquals(Target::TYPE_NAME, $target->type());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function name(TargetName $target)
    {
        $name = $target->name();
        static::assertInstanceOf(GeneralName::class, $name);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(TargetName $target)
    {
        static::assertIsString($target->string());
    }
}
