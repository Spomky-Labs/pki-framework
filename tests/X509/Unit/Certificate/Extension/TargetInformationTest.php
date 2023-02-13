<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Target;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetGroup;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetName;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Targets;
use SpomkyLabs\Pki\X509\Certificate\Extension\TargetInformationExtension;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;

/**
 * @internal
 */
final class TargetInformationTest extends TestCase
{
    final public const NAME_DN = 'cn=Target';

    final public const GROUP_DOMAIN = '.example.com';

    #[Test]
    public function createTargets()
    {
        $targets = Targets::create(
            TargetName::create(DirectoryName::fromDNString(self::NAME_DN)),
            TargetGroup::create(DNSName::create(self::GROUP_DOMAIN))
        );
        static::assertInstanceOf(Targets::class, $targets);
        return $targets;
    }

    #[Test]
    #[Depends('createTargets')]
    public function create(Targets $targets)
    {
        $ext = TargetInformationExtension::create(true, $targets);
        static::assertInstanceOf(TargetInformationExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_TARGET_INFORMATION, $ext->oid());
    }

    #[Test]
    #[Depends('create')]
    public function critical(Extension $ext)
    {
        static::assertTrue($ext->isCritical());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $ext = TargetInformationExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(TargetInformationExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(TargetInformationExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(TargetInformationExtension $ext)
    {
        $values = [];
        foreach ($ext as $target) {
            $values[] = $target;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(Target::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function verifyName(TargetInformationExtension $ext = null)
    {
        static::assertEquals(self::NAME_DN, $ext->names()[0]->string());
    }

    #[Test]
    #[Depends('create')]
    public function group(TargetInformationExtension $ext)
    {
        static::assertEquals(self::GROUP_DOMAIN, $ext->groups()[0]->string());
    }

    /**
     * Cover __clone method.
     */
    #[Test]
    #[Depends('create')]
    public function clone(TargetInformationExtension $ext)
    {
        static::assertInstanceOf(TargetInformationExtension::class, clone $ext);
    }

    #[Test]
    public function fromTargets()
    {
        $ext = TargetInformationExtension::fromTargets(TargetName::create(DirectoryName::fromDNString(self::NAME_DN)));
        static::assertInstanceOf(TargetInformationExtension::class, $ext);
    }
}
