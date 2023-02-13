<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function invalidASN1()
    {
        $el = ImplicitlyTaggedType::create(GeneralName::TAG_IP_ADDRESS, OctetString::create(''));
        $this->expectException(UnexpectedValueException::class);
        IPAddress::fromASN1($el);
    }
}
