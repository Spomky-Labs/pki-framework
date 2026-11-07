<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit;

use function in_array;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoBridge\Crypto\OpenSSLCrypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES128CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES192CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES256CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA1AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA224AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA384AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA512AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EncryptedPrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Exception\InvalidPasswordException;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use function sprintf;
use UnexpectedValueException;

/**
 * PKCS #8 EncryptedPrivateKeyInfo with PBES2.
 *
 * The fixtures in tests/assets/encrypted were made with OpenSSL 3.6 from rsa/private_key.pem, ec/private_key.pem and
 * rfc8410/ed25519_private_key.pem, with the password "password", for each of rsa, ec and ed25519 (`$in` being the
 * plaintext key):
 *
 *     openssl pkcs8 -topk8 -in $in -passout pass:password -v2 aes-256-cbc -v2prf hmacWithSHA256 \
 *         -out encrypted/${key}_aes256_sha256.pem
 *     openssl pkcs8 -topk8 -in $in -passout pass:password -v2 aes-128-cbc -v2prf hmacWithSHA1 \
 *         -out encrypted/${key}_aes128_sha1.pem
 *     openssl pkcs8 -topk8 -in $in -passout pass:password -v2 des3 -out encrypted/${key}_des3.pem
 *     openssl pkcs8 -topk8 -in $in -passout pass:password -v2 aes-192-cbc -v2prf hmacWithSHA512 \
 *         -out encrypted/${key}_aes192_sha512.pem
 *
 * and the unsupported or legacy ones:
 *
 *     openssl pkcs8 -topk8 -in rsa/private_key.pem -passout pass:password -scrypt -out encrypted/rsa_scrypt.pem
 *     openssl pkcs8 -topk8 -in rsa/private_key.pem -passout pass:password -v1 PBE-MD5-DES \
 *         -provider legacy -provider default -out encrypted/rsa_pbes1.pem
 *     openssl pkcs8 -topk8 -in ec/private_key.pem -passout pass:password -v2 des-cbc \
 *         -provider legacy -provider default -out encrypted/ec_des.pem
 *
 * OpenSSL uses 2048 PBKDF2 iterations for all of them.
 *
 * @internal
 */
final class EncryptedPrivateKeyInfoTest extends TestCase
{
    private const PASSWORD = 'password';

    /**
     * Iteration count for the keys the tests encrypt themselves, to keep them fast.
     */
    private const ITERATIONS = 1000;

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function fixtures(): iterable
    {
        $keys = [
            'rsa' => 'rsa/private_key.pem',
            'ec' => 'ec/private_key.pem',
            'ed25519' => 'rfc8410/ed25519_private_key.pem',
        ];
        $variants = [
            'aes256_sha256' => 'aes-256-cbc',
            'aes128_sha1' => 'aes-128-cbc',
            'des3' => 'des-ede3-cbc',
            'aes192_sha512' => 'aes-192-cbc',
        ];
        foreach ($keys as $key => $plain) {
            foreach ($variants as $variant => $cipher) {
                yield "{$key} {$variant}" => ["{$key}_{$variant}.pem", $plain, $cipher];
            }
        }
        yield 'ec des' => ['ec_des.pem', 'ec/private_key.pem', 'des-cbc'];
    }

    #[Test]
    #[DataProvider('fixtures')]
    public function decrypt(string $encrypted, string $plain, string $cipher): void
    {
        self::requireCipher($cipher);
        $epki = EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/' . $encrypted));
        $pki = $epki->decrypt(self::PASSWORD);
        static::assertSame(PEM::fromFile(TEST_ASSETS_DIR . '/' . $plain)->data(), $pki->toDER());
    }

    #[Test]
    #[DataProvider('fixtures')]
    public function fromEncryptedPEM(string $encrypted, string $plain, string $cipher): void
    {
        self::requireCipher($cipher);
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/' . $encrypted);
        $expected = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/' . $plain));
        static::assertSame($expected->toDER(), PrivateKeyInfo::fromEncryptedPEM($pem, self::PASSWORD)->toDER());
        static::assertSame(
            $expected->privateKey()
                ->toDER(),
            PrivateKey::fromEncryptedPEM($pem, self::PASSWORD)->toDER()
        );
    }

    #[Test]
    #[DataProvider('fixtures')]
    public function wrongPassword(string $encrypted, string $plain, string $cipher): void
    {
        self::requireCipher($cipher);
        $epki = EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/' . $encrypted));
        $this->expectException(InvalidPasswordException::class);
        $epki->decrypt('Password');
    }

    #[Test]
    #[DataProvider('fixtures')]
    public function derRoundTrip(string $encrypted, string $plain, string $cipher): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/' . $encrypted);
        $epki = EncryptedPrivateKeyInfo::fromPEM($pem);
        static::assertSame($pem->data(), $epki->toDER());
        static::assertEquals($pem, $epki->toPEM());
        // parsing needs no cipher
        static::assertNotSame('', $plain . $cipher);
    }

    #[Test]
    public function openSSLDefaultParameters(): void
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/rsa_aes256_sha256.pem'));
        $algo = $epki->encryptionAlgorithm();
        static::assertInstanceOf(PBES2AlgorithmIdentifier::class, $algo);
        $kdf = $algo->keyDerivationFunc();
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $kdf);
        static::assertSame(2048, $kdf->iterationCount());
        static::assertSame(16, mb_strlen($kdf->salt(), '8bit'));
        static::assertNull($kdf->keyLength());
        static::assertInstanceOf(HMACWithSHA256AlgorithmIdentifier::class, $kdf->prf());
        static::assertInstanceOf(AES256CBCAlgorithmIdentifier::class, $algo->encryptionScheme());
        static::assertSame(1232, mb_strlen($epki->encryptedData(), '8bit'));
    }

    #[Test]
    public function theDefaultPrfIsOmittedByOpenSSLAndDecodedAsHmacWithSHA1(): void
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/rsa_aes128_sha1.pem'));
        $algo = $epki->encryptionAlgorithm();
        static::assertInstanceOf(PBES2AlgorithmIdentifier::class, $algo);
        $kdf = $algo->keyDerivationFunc();
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $kdf);
        static::assertInstanceOf(HMACWithSHA1AlgorithmIdentifier::class, $kdf->prf());
        static::assertCount(2, $kdf->toASN1()->at(1)->asSequence());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function unsupported(): iterable
    {
        yield 'scrypt' => ['rsa_scrypt.pem', 'PBES2 key derivation function scrypt is not supported.'];
        yield 'PBES1' => [
            'rsa_pbes1.pem',
            'Encryption scheme PBES1 pbeWithMD5AndDES-CBC is not supported, only PBES2 is.',
        ];
    }

    #[Test]
    #[DataProvider('unsupported')]
    public function unsupportedSchemesAreNamed(string $encrypted, string $message): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/' . $encrypted);
        $epki = EncryptedPrivateKeyInfo::fromPEM($pem);
        // the structure itself is understood
        static::assertSame($pem->data(), $epki->toDER());
        try {
            $epki->decrypt(self::PASSWORD);
            static::fail('Expected an exception.');
        } catch (UnexpectedValueException $e) {
            static::assertNotInstanceOf(InvalidPasswordException::class, $e);
            static::assertSame($message, $e->getMessage());
        }
    }

    #[Test]
    public function anUnknownSchemeIsNamedByOID(): void
    {
        $epki = EncryptedPrivateKeyInfo::create(GenericAlgorithmIdentifier::create('1.2.3.4'), 'x');
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Encryption scheme 1.2.3.4 is not supported, only PBES2 is.');
        $epki->decrypt(self::PASSWORD);
    }

    #[Test]
    public function iterationCountLimit(): void
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/ec_aes128_sha1.pem'));
        static::assertSame(
            PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem')->data(),
            $epki->decrypt(self::PASSWORD, null, 2048)->toDER()
        );
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('PBKDF2 iteration count 2048 exceeds the maximum of 2047.');
        $epki->decrypt(self::PASSWORD, null, 2047);
    }

    #[Test]
    public function iterationCountLimitThroughFromEncryptedPEM(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/ec_aes128_sha1.pem');
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('PBKDF2 iteration count 2048 exceeds the maximum of 2047.');
        PrivateKey::fromEncryptedPEM($pem, self::PASSWORD, null, 2047);
    }

    #[Test]
    public function aHostileIterationCountIsRefusedByDefault(): void
    {
        $algo = self::algo(EncryptedPrivateKeyInfo::DEFAULT_MAX_ITERATION_COUNT + 1);
        $epki = EncryptedPrivateKeyInfo::create($algo, str_repeat("\0", 16));
        $started = microtime(true);
        try {
            PrivateKeyInfo::fromEncryptedPEM($epki->toPEM(), self::PASSWORD);
            static::fail('Expected an exception.');
        } catch (UnexpectedValueException $e) {
            static::assertSame(
                'PBKDF2 iteration count 2000001 exceeds the maximum of 2000000.',
                $e->getMessage()
            );
        }
        // nothing was derived
        static::assertLessThan(0.5, microtime(true) - $started);
    }

    #[Test]
    public function aCorruptedLastBlockIsReportedAsAWrongPassword(): void
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/rsa_aes256_sha256.pem'));
        $data = $epki->encryptedData();
        $data = self::flip($data, mb_strlen($data, '8bit') - 20, "\x01");
        $this->expectException(InvalidPasswordException::class);
        EncryptedPrivateKeyInfo::create($epki->encryptionAlgorithm(), $data)->decrypt(self::PASSWORD);
    }

    #[Test]
    public function aCorruptedFirstBlockIsReportedAsAWrongPassword(): void
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/ec_aes256_sha256.pem'));
        $data = $epki->encryptedData();
        $data = self::flip($data, 0, "\xFF");
        try {
            EncryptedPrivateKeyInfo::create($epki->encryptionAlgorithm(), $data)->decrypt(self::PASSWORD);
            static::fail('Expected an exception.');
        } catch (InvalidPasswordException $e) {
            static::assertSame('Invalid password or corrupted data.', $e->getMessage());
            // the padding was intact, it is the structure that failed to decode
            static::assertNotNull($e->getPrevious());
        }
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function truncations(): iterable
    {
        yield 'one byte short' => [1];
        yield 'all of it' => [1232];
    }

    #[Test]
    #[DataProvider('truncations')]
    public function aTruncatedCiphertextIsNotAWrongPassword(int $cut): void
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/rsa_aes256_sha256.pem'));
        $data = mb_substr($epki->encryptedData(), 0, -$cut, '8bit');
        try {
            EncryptedPrivateKeyInfo::create($epki->encryptionAlgorithm(), $data)->decrypt(self::PASSWORD);
            static::fail('Expected an exception.');
        } catch (UnexpectedValueException $e) {
            static::assertNotInstanceOf(InvalidPasswordException::class, $e);
            static::assertSame(sprintf(
                'Encrypted data length %d is not a positive multiple of the aes256-CBC block size.',
                1232 - $cut
            ), $e->getMessage());
        }
    }

    /**
     * @return iterable<string, array{AlgorithmIdentifierType, string, string}>
     */
    public static function prfsAndCiphers(): iterable
    {
        yield 'hmacWithSHA1 aes-128-cbc' => [
            HMACWithSHA1AlgorithmIdentifier::create(),
            'aes-128-cbc',
            AES128CBCAlgorithmIdentifier::class,
        ];
        yield 'hmacWithSHA224 aes-192-cbc' => [
            HMACWithSHA224AlgorithmIdentifier::create(NullType::create()),
            'aes-192-cbc',
            AES192CBCAlgorithmIdentifier::class,
        ];
        yield 'hmacWithSHA256 aes-256-cbc' => [
            HMACWithSHA256AlgorithmIdentifier::create(NullType::create()),
            'aes-256-cbc',
            AES256CBCAlgorithmIdentifier::class,
        ];
        yield 'hmacWithSHA384 des-ede3-cbc' => [
            HMACWithSHA384AlgorithmIdentifier::create(NullType::create()),
            'des-ede3-cbc',
            DESEDE3CBCAlgorithmIdentifier::class,
        ];
        yield 'hmacWithSHA512 without NULL des-cbc' => [
            HMACWithSHA512AlgorithmIdentifier::create(),
            'des-cbc',
            DESCBCAlgorithmIdentifier::class,
        ];
    }

    /**
     * @param class-string<BlockCipherAlgorithmIdentifier> $cipherClass
     */
    #[Test]
    #[DataProvider('prfsAndCiphers')]
    public function encryptOpensWithOpenSSL(AlgorithmIdentifierType $prf, string $cipher, string $cipherClass): void
    {
        self::requireCipher($cipher);
        $ivSize = in_array($cipher, ['des-cbc', 'des-ede3-cbc'], true) ? 8 : 16;
        /** @var BlockCipherAlgorithmIdentifier $scheme */
        $scheme = $cipherClass::create(random_bytes($ivSize));
        $algo = PBES2AlgorithmIdentifier::create(
            PBKDF2AlgorithmIdentifier::create(random_bytes(16), self::ITERATIONS, null, $prf),
            $scheme
        );
        foreach (['rsa/private_key.pem', 'ec/private_key.pem', 'rfc8410/ed25519_private_key.pem'] as $plain) {
            $key = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/' . $plain));
            $pem = EncryptedPrivateKeyInfo::encrypt($key, self::PASSWORD, $algo, new OpenSSLCrypto())->toPEM();
            static::assertSame(PEM::TYPE_ENCRYPTED_PRIVATE_KEY, $pem->type());
            static::assertSame(
                $key->toDER(),
                PrivateKeyInfo::fromEncryptedPEM(PEM::fromString($pem->string()), self::PASSWORD)->toDER()
            );
            self::assertOpenSSLOpens($pem, $key);
        }
    }

    #[Test]
    public function encryptWithDefaults(): void
    {
        $key = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $epki = EncryptedPrivateKeyInfo::encrypt($key, self::PASSWORD);
        $algo = $epki->encryptionAlgorithm();
        static::assertInstanceOf(PBES2AlgorithmIdentifier::class, $algo);
        $kdf = $algo->keyDerivationFunc();
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $kdf);
        static::assertSame(EncryptedPrivateKeyInfo::DEFAULT_ITERATION_COUNT, $kdf->iterationCount());
        static::assertSame($key->toDER(), $epki->decrypt(self::PASSWORD)->toDER());
        self::assertOpenSSLOpens($epki->toPEM(), $key);
    }

    #[Test]
    public function defaultEncryptionAlgorithm(): void
    {
        $algo = EncryptedPrivateKeyInfo::defaultEncryptionAlgorithm(4096);
        $kdf = $algo->keyDerivationFunc();
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $kdf);
        static::assertSame(4096, $kdf->iterationCount());
        static::assertSame(16, mb_strlen($kdf->salt(), '8bit'));
        static::assertNull($kdf->keyLength());
        static::assertInstanceOf(HMACWithSHA256AlgorithmIdentifier::class, $kdf->prf());
        $cipher = $algo->encryptionScheme();
        static::assertInstanceOf(AES256CBCAlgorithmIdentifier::class, $cipher);
        // OpenSSL writes the NULL parameters of hmacWithSHA256, so does this
        static::assertSame(
            Sequence::create(ObjectIdentifier::create('1.2.840.113549.2.9'), NullType::create())->toDER(),
            $kdf->prf()
                ->toASN1()
                ->toDER()
        );
        $other = EncryptedPrivateKeyInfo::defaultEncryptionAlgorithm();
        $otherKdf = $other->keyDerivationFunc();
        static::assertInstanceOf(PBKDF2AlgorithmIdentifier::class, $otherKdf);
        static::assertNotSame($kdf->salt(), $otherKdf->salt());
        static::assertInstanceOf(AES256CBCAlgorithmIdentifier::class, $other->encryptionScheme());
        static::assertNotSame($cipher->initializationVector(), $other->encryptionScheme()->initializationVector());
        static::assertSame(EncryptedPrivateKeyInfo::DEFAULT_ITERATION_COUNT, $otherKdf->iterationCount());
    }

    #[Test]
    public function aOneAsymmetricKeyKeepsItsPublicKey(): void
    {
        $key = OneAsymmetricKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem'));
        static::assertTrue($key->hasPublicKeyData());
        $decrypted = EncryptedPrivateKeyInfo::encrypt($key, self::PASSWORD, self::algo(self::ITERATIONS))
            ->decrypt(self::PASSWORD);
        static::assertSame($key->toDER(), $decrypted->toDER());
        static::assertSame(OneAsymmetricKey::VERSION_2, $decrypted->version());
    }

    #[Test]
    public function aStatedKeyLengthThatMatchesTheCipher(): void
    {
        $key = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem'));
        $algo = PBES2AlgorithmIdentifier::create(
            PBKDF2AlgorithmIdentifier::create(random_bytes(16), self::ITERATIONS, 32),
            AES256CBCAlgorithmIdentifier::create(random_bytes(16))
        );
        $epki = EncryptedPrivateKeyInfo::encrypt($key, self::PASSWORD, $algo);
        static::assertSame($key->toDER(), $epki->decrypt(self::PASSWORD)->toDER());
        self::assertOpenSSLOpens($epki->toPEM(), $key);
    }

    /**
     * @return iterable<string, array{PBES2AlgorithmIdentifier, string}>
     */
    public static function unsupportedParameters(): iterable
    {
        $kdf = PBKDF2AlgorithmIdentifier::create('saltsalt', 1);
        $aes = AES128CBCAlgorithmIdentifier::create('0123456789abcdef');
        yield 'a key length that does not match the cipher' => [
            PBES2AlgorithmIdentifier::create(PBKDF2AlgorithmIdentifier::create('saltsalt', 1, 32), $aes),
            'PBKDF2 key length 32 does not match the 16 byte key of aes128-CBC.',
        ];
        yield 'a hash that is not an HMAC' => [
            PBES2AlgorithmIdentifier::create(
                PBKDF2AlgorithmIdentifier::create('saltsalt', 1, null, SHA256AlgorithmIdentifier::create()),
                $aes
            ),
            'PBKDF2 pseudorandom function sha256 is not supported.',
        ];
        yield 'an unknown pseudorandom function' => [
            PBES2AlgorithmIdentifier::create(
                PBKDF2AlgorithmIdentifier::create('saltsalt', 1, null, GenericAlgorithmIdentifier::create('1.2.3')),
                $aes
            ),
            'PBKDF2 pseudorandom function 1.2.3 is not supported.',
        ];
        yield 'an unknown key derivation function' => [
            PBES2AlgorithmIdentifier::create(GenericAlgorithmIdentifier::create('1.2.3'), $aes),
            'PBES2 key derivation function 1.2.3 is not supported.',
        ];
        yield 'RC2' => [
            PBES2AlgorithmIdentifier::create($kdf, RC2CBCAlgorithmIdentifier::create(128, '01234567')),
            'PBES2 encryption scheme rc2-cbc is not supported.',
        ];
        yield 'AES-GCM' => [
            PBES2AlgorithmIdentifier::create($kdf, GenericAlgorithmIdentifier::create('2.16.840.1.101.3.4.1.46')),
            'PBES2 encryption scheme 2.16.840.1.101.3.4.1.46 is not supported.',
        ];
    }

    #[Test]
    #[DataProvider('unsupportedParameters')]
    public function unsupportedParametersAreRefusedOnDecrypt(PBES2AlgorithmIdentifier $algo, string $message): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage($message);
        EncryptedPrivateKeyInfo::create($algo, str_repeat("\0", 16))->decrypt(self::PASSWORD);
    }

    #[Test]
    #[DataProvider('unsupportedParameters')]
    public function unsupportedParametersAreRefusedOnEncrypt(PBES2AlgorithmIdentifier $algo, string $message): void
    {
        $key = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem'));
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage($message);
        EncryptedPrivateKeyInfo::encrypt($key, self::PASSWORD, $algo);
    }

    #[Test]
    public function fromPEMRefusesOtherTypes(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid PEM type.');
        EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    #[Test]
    public function fromASN1RefusesExtraElements(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('EncryptedPrivateKeyInfo must have exactly two elements.');
        EncryptedPrivateKeyInfo::fromASN1(Sequence::create(
            self::algo(1)->toASN1(),
            OctetString::create('x'),
            OctetString::create('y')
        ));
    }

    #[Test]
    public function fromASN1RefusesAMissingElement(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('EncryptedPrivateKeyInfo must have exactly two elements.');
        EncryptedPrivateKeyInfo::fromASN1(Sequence::create(self::algo(1)->toASN1()));
    }

    #[Test]
    public function legacyFromEncryptedPEM(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_rsa_aes256.pem');
        $expected = RSAPrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem'));
        $pki = PrivateKeyInfo::fromEncryptedPEM($pem, self::PASSWORD);
        static::assertSame($expected->toDER(), $pki->privateKeyData());
        $key = PrivateKey::fromEncryptedPEM($pem, self::PASSWORD);
        static::assertInstanceOf(RSAPrivateKey::class, $key);
        static::assertSame($expected->toDER(), $key->toDER());
        $ec = PrivateKey::fromEncryptedPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_ec_des3.pem'),
            self::PASSWORD,
            new OpenSSLCrypto()
        );
        static::assertInstanceOf(ECPrivateKey::class, $ec);
    }

    #[Test]
    public function legacyWrongPassword(): void
    {
        $this->expectException(InvalidPasswordException::class);
        PrivateKey::fromEncryptedPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_ec_aes128.pem'), 'nope');
    }

    #[Test]
    public function legacyDataThatIsNotAKeyOfTheStatedTypeIsReportedAsAWrongPassword(): void
    {
        // decrypts to a single DER SEQUENCE, the RSA key, which the EC label then fails to decode
        $rsa = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_rsa_aes256.pem');
        $pem = PEM::create(PEM::TYPE_EC_PRIVATE_KEY, $rsa->data(), $rsa->headers());
        try {
            PrivateKeyInfo::fromEncryptedPEM($pem, self::PASSWORD);
            static::fail('Expected an exception.');
        } catch (InvalidPasswordException $e) {
            static::assertSame('Invalid password or corrupted data.', $e->getMessage());
            static::assertNotNull($e->getPrevious());
        }
    }

    #[Test]
    public function legacyUnsupportedTypeIsRefusedBeforeDecryption(): void
    {
        $rsa = PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/legacy_rsa_aes256.pem');
        $pem = PEM::create('DSA PRIVATE KEY', $rsa->data(), $rsa->headers());
        try {
            // a wrong password would be reported as such if the data were decrypted first
            PrivateKeyInfo::fromEncryptedPEM($pem, 'nope');
            static::fail('Expected an exception.');
        } catch (UnexpectedValueException $e) {
            static::assertNotInstanceOf(InvalidPasswordException::class, $e);
            static::assertSame(
                'Encrypted PEM type DSA PRIVATE KEY is not supported, only RSA PRIVATE KEY and EC PRIVATE KEY are.',
                $e->getMessage()
            );
        }
    }

    #[Test]
    public function fromEncryptedPEMRefusesAPlainKey(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('PEM is not encrypted.');
        PrivateKeyInfo::fromEncryptedPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'), self::PASSWORD);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function encryptedPEMs(): iterable
    {
        yield 'PKCS #8' => ['rsa_aes256_sha256.pem'];
        yield 'traditional' => ['legacy_rsa_aes256.pem'];
    }

    #[Test]
    #[DataProvider('encryptedPEMs')]
    public function privateKeyFromPEMPointsToFromEncryptedPEM(string $file): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('PEM is encrypted, use PrivateKey::fromEncryptedPEM().');
        PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/' . $file));
    }

    #[Test]
    #[DataProvider('encryptedPEMs')]
    public function privateKeyInfoFromPEMPointsToFromEncryptedPEM(string $file): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('PEM is encrypted, use PrivateKeyInfo::fromEncryptedPEM().');
        PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/encrypted/' . $file));
    }

    private static function algo(int $iterationCount): PBES2AlgorithmIdentifier
    {
        return PBES2AlgorithmIdentifier::create(
            PBKDF2AlgorithmIdentifier::create(random_bytes(16), $iterationCount),
            AES128CBCAlgorithmIdentifier::create(random_bytes(16))
        );
    }

    private static function assertOpenSSLOpens(PEM $pem, OneAsymmetricKey $key): void
    {
        $opened = openssl_pkey_get_private($pem->string(), self::PASSWORD);
        static::assertNotFalse($opened, (string) openssl_error_string());
        $details = openssl_pkey_get_details($opened);
        static::assertIsArray($details);
        // the library cannot derive every public key, OpenSSL can: compare with what it makes of the plaintext
        $expected = openssl_pkey_get_details(self::openssl($key->toPEM()->string()));
        static::assertIsArray($expected);
        static::assertSame($expected['key'], $details['key']);
        static::assertFalse(@openssl_pkey_get_private($pem->string(), 'wrong'));
        while (openssl_error_string() !== false) {
            // drain the queue the wrong password left behind
        }
    }

    private static function openssl(string $pem): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_private($pem);
        static::assertNotFalse($key);
        return $key;
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
