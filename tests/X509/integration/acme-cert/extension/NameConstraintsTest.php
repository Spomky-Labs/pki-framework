<?php

declare(strict_types=1);

namespace integration\acme-cert\extension;

use Extensions;
use integration\acmeuse;
use RefExtTestHelper;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use Sop\X509\Certificate\Extension\NameConstraintsExtension;

Sop\X509\Certificate\Extension\Extension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefNameConstraintsTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
     * @return NameConstraintsExtension
     */
    public function testNameConstraintsExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_NAME_CONSTRAINTS);
        $this->assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testNameConstraintsExtension
     *
     * @param NameConstraintsExtension $bc
     *
     * @return GeneralSubtrees
     */
    public function testNameConstraintPermittedSubtrees(
        NameConstraintsExtension $nc)
    {
        $subtrees = $nc->permittedSubtrees();
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends testNameConstraintPermittedSubtrees
     *
     * @param GeneralSubtrees $gs
     */
    public function testNameConstraintPermittedDomain(GeneralSubtrees $gs)
    {
        $this->assertEquals('.example.com',
            $gs->all()[0]->base()
                ->name());
    }
}
