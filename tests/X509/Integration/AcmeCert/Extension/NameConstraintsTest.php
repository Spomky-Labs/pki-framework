<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use Sop\X509\Certificate\Extension\NameConstraintsExtension;

/**
 * @internal
 */
final class NameConstraintsTest extends RefExtTestHelper
{
    /**
     * @return NameConstraintsExtension
     *
     * @test
     */
    public function nameConstraintsExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_NAME_CONSTRAINTS);
        $this->assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends nameConstraintsExtension
     *
     * @return GeneralSubtrees
     *
     * @test
     */
    public function nameConstraintPermittedSubtrees(NameConstraintsExtension $nc)
    {
        $subtrees = $nc->permittedSubtrees();
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends nameConstraintPermittedSubtrees
     *
     * @test
     */
    public function nameConstraintPermittedDomain(GeneralSubtrees $gs)
    {
        $this->assertEquals('.example.com', $gs->all()[0] ->base() ->name());
    }
}
