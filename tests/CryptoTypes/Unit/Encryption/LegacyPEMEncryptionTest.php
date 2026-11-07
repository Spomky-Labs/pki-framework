<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\Encryption;

use function in_array;
use const OPENSSL_RAW_DATA;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Encryption\LegacyPEMEncryption;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Exception\InvalidPasswordException;
use UnexpectedValueException;

/**
 * Traditional OpenSSL encrypted PEM (RFC 1421 `Proc-Type`/`DEK-Info`).
 *
 * The fixtures in tests/assets/encrypted were made with OpenSSL 3.6 from the plaintext keys next to them, with the
 * password "password":
 *
 *     openssl rsa -in rsa/rsa_private_key.pem -aes256 -traditional -passout pass:password \
 *         -out encrypted/legacy_rsa_aes256.pem
 *     openssl rsa -in rsa/rsa_private_key.pem -aes192 -traditional -passout pass:password \
 *         -out encrypted/legacy_rsa_aes192.pem
 *     openssl rsa -in rsa/rsa_private_key.pem -aes128 -traditional -passout pass:password \
 *         -out encrypted/legacy_rsa_aes128.pem
 *     openssl ec -in ec/ec_private_key.pem -des3 -passout pass:password -out encrypted/legacy_ec_des3.pem
 *     openssl ec -in ec/ec_private_key.pem -aes128 -passout pass:password -out encrypted/legacy_ec_aes128.pem
 *     openssl ec -in ec/ec_private_key.pem -des -provider legacy -provider default -passout pass:password \
 *         -out encrypted/legacy_ec_des.pem
 *
 * @internal
 */
final class LegacyPEMEncryptionTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function fixtures(): iterable
    {
        yield 'RSA AES-256-CBC' => ['legacy_rsa_aes256.pem', 'rsa/rsa_private_key.pem', 'aes-256-cbc'];
        yield 'RSA AES-192-CBC' => ['legacy_rsa_aes192.pem', 'rsa/rsa_private_key.pem', 'aes-192-cbc'];
        yield 'RSA AES-128-CBC' => ['legacy_rsa_aes128.pem', 'rsa/rsa_private_key.pem', 'aes-128-cbc'];
        yield 'EC DES-EDE3-CBC' => ['legacy_ec_des3.pem', 'ec/ec_private_key.pem', 'des-ede3-cbc'];
        yield 'EC AES-128-CBC' => ['legacy_ec_aes128.pem', 'ec/ec_private_key.pem', 'aes-128-cbc'];
        yield 'EC DES-CBC' => ['legacy_ec_des.pem', 'ec/ec_private_key.pem', 'des-cbc'];
    }

    #[Test]
    #[DataProvider('fixtures')]
    public function decrypt(string $encrypted, string $plain, string $cipher): void
    {
        self::requireCipher($cipher);
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/' . $encrypted);
        $expected = PEM::fromFile(TEST_ASSETS_DIR . '/' . $plain);
        $decrypted = LegacyPEMEncryption::decrypt($pem, 'password');
        static::assertSame($expected->type(), $decrypted->type());
        static::assertSame($expected->data(), $decrypted->data());
        static::assertSame([], $decrypted->headers());
    }

    #[Test]
    #[DataProvider('fixtures')]
    public function wrongPassword(string $encrypted, string $plain, string $cipher): void
    {
        self::requireCipher($cipher);
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/' . $encrypted);
        $this->expectException(InvalidPasswordException::class);
        LegacyPEMEncryption::decrypt($pem, 'Password');
    }

    #[Test]
    public function bytesToKeyMatchesOpenSSL(): void
    {
        // openssl enc -aes-256-cbc -pass pass:password -S 0102030405060708 -md md5 -P
        // prints the 32 byte key followed by the 16 byte IV, that is three rounds of the derivation
        $salt = (string) hex2bin('0102030405060708');
        static::assertSame(
            'e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3457b99436b51ce02' .
            '8d450e2ed75a84a923d4eac9fe49226b',
            bin2hex(LegacyPEMEncryption::bytesToKey('password', $salt, 48))
        );
        static::assertSame(
            'e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3457b99436b51ce',
            bin2hex(LegacyPEMEncryption::bytesToKey('password', $salt, 31))
        );
        static::assertSame('e7b0971e52ca5cc8', bin2hex(LegacyPEMEncryption::bytesToKey('password', $salt, 8)));
        static::assertSame('', LegacyPEMEncryption::bytesToKey('password', $salt, 0));
    }

    #[Test]
    public function aCorruptedLastBlockIsReportedAsAWrongPassword(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_rsa_aes256.pem');
        $data = $pem->data();
        $data = self::flip($data, mb_strlen($data, '8bit') - 20, "\x01");
        $this->expectException(InvalidPasswordException::class);
        LegacyPEMEncryption::decrypt(PEM::create($pem->type(), $data, $pem->headers()), 'password');
    }

    #[Test]
    public function aCorruptedFirstBlockIsReportedAsAWrongPassword(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_ec_aes128.pem');
        $data = $pem->data();
        $data = self::flip($data, 0, "\xFF");
        $this->expectException(InvalidPasswordException::class);
        LegacyPEMEncryption::decrypt(PEM::create($pem->type(), $data, $pem->headers()), 'password');
    }

    #[Test]
    public function trailingDataIsReportedAsAWrongPassword(): void
    {
        // a valid key followed by a block of data that is not part of it: padded and encrypted like the real thing
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_ec_aes128.pem');
        $iv = (string) hex2bin(explode(',', (string) $pem->header('DEK-Info'))[1]);
        $key = LegacyPEMEncryption::bytesToKey('password', mb_substr($iv, 0, 8, '8bit'), 16);
        $plain = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem')->data() . "\x05\x00";
        $data = (string) openssl_encrypt($plain, 'aes-128-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $this->expectException(InvalidPasswordException::class);
        LegacyPEMEncryption::decrypt(PEM::create($pem->type(), $data, $pem->headers()), 'password');
    }

    #[Test]
    public function aValidStructureIsAccepted(): void
    {
        // the same construction as above, without the trailing data
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_ec_aes128.pem');
        $iv = (string) hex2bin(explode(',', (string) $pem->header('DEK-Info'))[1]);
        $key = LegacyPEMEncryption::bytesToKey('password', mb_substr($iv, 0, 8, '8bit'), 16);
        $plain = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem')->data();
        $data = (string) openssl_encrypt($plain, 'aes-128-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $decrypted = LegacyPEMEncryption::decrypt(PEM::create($pem->type(), $data, $pem->headers()), 'password');
        static::assertSame($plain, $decrypted->data());
    }

    #[Test]
    public function aNonSequenceIsReportedAsAWrongPassword(): void
    {
        $iv = str_repeat("\x00", 16);
        $key = LegacyPEMEncryption::bytesToKey('password', mb_substr($iv, 0, 8, '8bit'), 16);
        // a complete DER INTEGER, which no traditional key is
        $data = (string) openssl_encrypt("\x02\x01\x05", 'aes-128-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $this->expectException(InvalidPasswordException::class);
        LegacyPEMEncryption::decrypt(PEM::create('RSA PRIVATE KEY', $data, [
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => 'aes-128-cbc,' . bin2hex($iv),
        ]), 'password');
    }

    /**
     * @return iterable<string, array{array<string, string>, string, string}>
     */
    public static function malformed(): iterable
    {
        $iv16 = '00112233445566778899AABBCCDDEEFF';
        $data = str_repeat('x', 32);
        yield 'not encrypted' => [[], $data, 'PEM is not encrypted.'];
        yield 'MIC-ONLY' => [[
            'Proc-Type' => '4,MIC-ONLY',
        ], $data, 'PEM is not encrypted.'];
        yield 'no DEK-Info' => [[
            'Proc-Type' => '4,ENCRYPTED',
        ], $data, 'Missing or malformed DEK-Info header.'];
        yield 'DEK-Info without IV' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => 'AES-128-CBC',
        ], $data, 'Missing or malformed DEK-Info header.'];
        yield 'DEK-Info with a non hex IV' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => 'AES-128-CBC,XY',
        ], $data, 'Missing or malformed DEK-Info header.'];
        yield 'DEK-Info with trailing data' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => "AES-128-CBC,{$iv16},x",
        ], $data, 'Missing or malformed DEK-Info header.'];
        yield 'an odd number of IV digits' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => 'AES-128-CBC,' . mb_substr($iv16, 1),
        ], $data, 'Invalid IV in DEK-Info header.'];
        yield 'a short AES IV' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => 'AES-128-CBC,0011223344556677',
        ], $data, 'Invalid IV in DEK-Info header.'];
        yield 'a long DES IV' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => "DES-EDE3-CBC,{$iv16}",
        ], $data, 'Invalid IV in DEK-Info header.'];
        yield 'a long single DES IV' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => "DES-CBC,{$iv16}",
        ], $data, 'Invalid IV in DEK-Info header.'];
        yield 'an unsupported cipher' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => "AES-128-CFB,{$iv16}",
        ], $data, 'DEK-Info cipher AES-128-CFB is not supported.'];
        yield 'a ciphertext that is not a whole number of blocks' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => "AES-128-CBC,{$iv16}",
        ], str_repeat('x', 31), 'Encrypted data length 31 is not a positive multiple of the aes128-CBC block size.'];
        yield 'an empty ciphertext' => [[
            'Proc-Type' => '4,ENCRYPTED',
            'DEK-Info' => "AES-128-CBC,{$iv16}",
        ], '', 'Encrypted data length 0 is not a positive multiple of the aes128-CBC block size.'];
    }

    /**
     * @param array<string, string> $headers
     */
    #[Test]
    #[DataProvider('malformed')]
    public function malformedInputIsRefused(array $headers, string $data, string $message): void
    {
        try {
            LegacyPEMEncryption::decrypt(PEM::create('RSA PRIVATE KEY', $data, $headers), 'password');
            static::fail('Expected an exception.');
        } catch (UnexpectedValueException $e) {
            static::assertNotInstanceOf(InvalidPasswordException::class, $e);
            static::assertSame($message, $e->getMessage());
        }
    }

    #[Test]
    public function aLowerCaseCipherNameIsAccepted(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_ec_des3.pem');
        $headers = $pem->headers();
        $headers['DEK-Info'] = strtolower($headers['DEK-Info']);
        $decrypted = LegacyPEMEncryption::decrypt(PEM::create($pem->type(), $pem->data(), $headers), 'password');
        static::assertSame(PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem')->data(), $decrypted->data());
    }

    /**
     * XOR one byte of the data with a mask.
     */
    private static function flip(string $data, int $offset, string $mask): string
    {
        return substr_replace($data, $data[$offset] ^ $mask, $offset, 1);
    }

    private static function requireCipher(string $cipher): void
    {
        if (! in_array($cipher, openssl_get_cipher_methods(), true)) {
            static::markTestSkipped(
                "The OpenSSL of this runtime has no {$cipher}; OpenSSL 3 needs the legacy provider for single DES."
            );
        }
    }
}
