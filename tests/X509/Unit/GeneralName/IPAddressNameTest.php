<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\IPAddress;
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
