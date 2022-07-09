<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\IPAddress;
use UnexpectedValueException;

/**
 * @internal
 */
final class IPAddressNameTest extends TestCase
{
    /**
     * @test
     */
    public function invalidASN1()
    {
        $el = new ImplicitlyTaggedType(GeneralName::TAG_IP_ADDRESS, new OctetString(''));
        $this->expectException(UnexpectedValueException::class);
        IPAddress::fromASN1($el);
    }
}
