<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraintsExtension;

/**
 * @internal
 */
final class NameConstraintsTest extends RefExtTestHelper
{
    #[Test]
    public function nameConstraintsExtension(): NameConstraintsExtension
    {
        $ext = self::$_extensions->get(Extension::OID_NAME_CONSTRAINTS);
        static::assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('nameConstraintsExtension')]
    public function nameConstraintPermittedSubtrees(NameConstraintsExtension $nc): GeneralSubtrees
    {
        $subtrees = $nc->permittedSubtrees();
        static::assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    #[Test]
    #[Depends('nameConstraintPermittedSubtrees')]
    public function nameConstraintPermittedDomain(GeneralSubtrees $gs)
    {
        static::assertSame('.example.com', $gs->all()[0]->base()->name());
    }
}
