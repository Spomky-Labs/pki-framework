<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Util\Flags;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;

/**
 * A named bit list numbers bit zero as the most significant bit of the first octet, so the flags of a nine bit
 * field are the leading nine bits of the string. A BIT STRING wider than the field used to be masked down to its
 * *last* nine bits instead, which reads every usage from the wrong offset: a certificate asserting no usage at all
 * was reported as asserting keyCertSign, and a certificate asserting cRLSign was reported as asserting nothing.
 *
 * Such an encoding is valid DER as long as the final bit is set, so nothing upstream rejects it.
 *
 * @internal
 */
final class KeyUsageBitStringTest extends TestCase
{
    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function overLongEncodings(): iterable
    {
        // 16 bits, only bits 12 and 15 set: no bit of the named list is asserted.
        yield 'bits 12 and 15, none of the named list' => ['0303000009', []];
        // 16 bits, bit 6 (cRLSign) and bit 15 set.
        yield 'bit 6 and bit 15' => ['0303000201', ['cRLSign']];
        // 18 bits, bit 0 (digitalSignature) and bit 17 set.
        yield 'bit 0 and bit 17' => ['030406800040', ['digitalSignature']];
        // 24 bits, bit 5 (keyCertSign) and bit 23 set.
        yield 'bit 5 and bit 23' => ['0304000400 01', ['keyCertSign']];
    }

    #[Test]
    #[DataProvider('overLongEncodings')]
    public function surplusBitsDoNotShiftTheNamedBitList(string $bitStringHex, array $expected): void
    {
        $extension = self::keyUsage($bitStringHex);
        static::assertInstanceOf(KeyUsageExtension::class, $extension);
        static::assertSame($expected, self::assertedUsages($extension));
    }

    #[Test]
    public function conformantEncodingsAreUnchanged(): void
    {
        // Six bits, bit 5 set: the ordinary encoding of a CA certificate's keyUsage.
        static::assertSame(['keyCertSign'], self::assertedUsages(self::keyUsage('03020204')));
        // One bit, bit 0 set.
        static::assertSame(['digitalSignature'], self::assertedUsages(self::keyUsage('03020780')));
        // Nine bits, every bit set.
        static::assertCount(9, self::assertedUsages(self::keyUsage('0303 07 FF80')));
    }

    #[Test]
    public function anOverLongBitStringKeepsItsLeadingBits(): void
    {
        // 0x8000 is bit 0 alone in a sixteen bit string; only the first of the leading nine bits is set.
        $flags = Flags::fromBitString(BitString::create("\x80\x00"), 9);
        static::assertSame('100000000', self::bits($flags));
        // 0x0001 is bit 15 alone, which is outside the field; none of the leading nine bits is set.
        $flags = Flags::fromBitString(BitString::create("\x00\x01"), 9);
        static::assertSame('000000000', self::bits($flags));
    }

    private static function bits(Flags $flags): string
    {
        $out = '';
        for ($i = 0; $i < 9; ++$i) {
            $out .= $flags->test($i) ? '1' : '0';
        }

        return $out;
    }

    private static function keyUsage(string $bitStringHex): Extension
    {
        $der = hex2bin(str_replace(' ', '', $bitStringHex));
        static::assertIsString($der);

        return Extension::fromASN1(Sequence::create(
            ObjectIdentifier::create(Extension::OID_KEY_USAGE),
            Boolean::create(true),
            OctetString::create($der),
        ));
    }

    /**
     * @return list<string>
     */
    private static function assertedUsages(Extension $extension): array
    {
        static::assertInstanceOf(KeyUsageExtension::class, $extension);
        $usages = [];
        foreach ([
            'digitalSignature' => $extension->isDigitalSignature(),
            'nonRepudiation' => $extension->isNonRepudiation(),
            'keyEncipherment' => $extension->isKeyEncipherment(),
            'dataEncipherment' => $extension->isDataEncipherment(),
            'keyAgreement' => $extension->isKeyAgreement(),
            'keyCertSign' => $extension->isKeyCertSign(),
            'cRLSign' => $extension->isCRLSign(),
            'encipherOnly' => $extension->isEncipherOnly(),
            'decipherOnly' => $extension->isDecipherOnly(),
        ] as $name => $isSet) {
            if ($isSet) {
                $usages[] = $name;
            }
        }

        return $usages;
    }
}
