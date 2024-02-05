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
    public function oID(): void
    {
        $ext = self::createExtension();
        static::assertSame(Extension::OID_TARGET_INFORMATION, $ext->oid());
        static::assertTrue($ext->isCritical());
        static::assertCount(2, $ext);
        $values = [];
        foreach ($ext as $target) {
            $values[] = $target;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(Target::class, $values);
        static::assertSame(self::NAME_DN, $ext->names()[0]->string());
        static::assertSame(self::GROUP_DOMAIN, $ext->groups()[0]->string());
        static::assertInstanceOf(TargetInformationExtension::class, clone $ext);
    }

    #[Test]
    public function encode(): string
    {
        $ext = self::createExtension();
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $der): TargetInformationExtension
    {
        $ext = TargetInformationExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(TargetInformationExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('decode')]
    public function recoded(Extension $new): void
    {
        $ext = self::createExtension();
        static::assertEquals($ext, $new);
    }

    #[Test]
    public function fromTargets(): void
    {
        $ext = TargetInformationExtension::fromTargets(TargetName::create(DirectoryName::fromDNString(self::NAME_DN)));
        static::assertInstanceOf(TargetInformationExtension::class, $ext);
    }

    private static function createExtension(): TargetInformationExtension
    {
        $targets = Targets::create(
            TargetName::create(DirectoryName::fromDNString(self::NAME_DN)),
            TargetGroup::create(DNSName::create(self::GROUP_DOMAIN))
        );

        return TargetInformationExtension::create(true, $targets);
    }
}
