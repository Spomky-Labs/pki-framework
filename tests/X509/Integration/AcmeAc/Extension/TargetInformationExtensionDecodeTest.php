<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeAc\Extension;

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\Target\Target;
use Sop\X509\Certificate\Extension\TargetInformationExtension;

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
        $this->assertInstanceOf(TargetInformationExtension::class, $ext);
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
        $this->assertCount(3, $targets);
    }

    /**
     * @depends extension
     *
     * @test
     */
    public function values(TargetInformationExtension $ti)
    {
        $vals = array_map(function (Target $target) {
            return $target->string();
        }, $ti->targets()  ->all());
        $this->assertEqualsCanonicalizing(['urn:test', '*.example.com', 'urn:another'], $vals);
    }
}
