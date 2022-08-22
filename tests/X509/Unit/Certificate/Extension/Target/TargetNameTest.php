<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\Target;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Target;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

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
        $target = TargetName::create(UniformResourceIdentifier::create(self::URI));
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
