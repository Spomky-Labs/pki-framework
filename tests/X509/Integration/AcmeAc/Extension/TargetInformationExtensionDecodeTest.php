<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeAc\Extension;

use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\Target;
use SpomkyLabs\Pki\X509\Certificate\Extension\TargetInformationExtension;

require_once __DIR__ . '/RefACExtTestHelper.php';

/**
 * @internal
 */
final class TargetInformationExtensionDecodeTest extends RefACExtTestHelper
{
    /**
     * @test
     */
    public function extension()
    {
        $ext = self::$_extensions->get(Extension::OID_TARGET_INFORMATION);
        static::assertInstanceOf(TargetInformationExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends extension
     *
     * @test
     */
    public function countMethod(TargetInformationExtension $ti)
    {
        $targets = $ti->targets();
        static::assertCount(3, $targets);
    }

    /**
     * @depends extension
     *
     * @test
     */
    public function values(TargetInformationExtension $ti)
    {
        $vals = array_map(fn (Target $target) => $target->string(), $ti->targets() ->all());
        static::assertEqualsCanonicalizing(['urn:test', '*.example.com', 'urn:another'], $vals);
    }
}
