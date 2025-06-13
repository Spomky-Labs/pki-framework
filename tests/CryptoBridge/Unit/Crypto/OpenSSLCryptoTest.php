<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoBridge\Unit\Crypto;

use BadMethodCallException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoBridge\Crypto\OpenSSLCrypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES128CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES192CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES256CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA224AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA384AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA512AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\MD2WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\MD4WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\MD5WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA224WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA384WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Signature\RSASignature;
use SpomkyLabs\Pki\CryptoTypes\Signature\Signature;
use UnexpectedValueException;

/**
 * @internal
 */
#[RequiresPhpExtension('openssl')]
final class OpenSSLCryptoTest extends TestCase
{
    public const DATA = 'PAYLOAD';

    private static ?OpenSSLCrypto $_crypto;

    private static ?OneAsymmetricKey $_rsaPrivKeyInfo = null;

    private static ?OneAsymmetricKey $_ecPrivKeyInfo = null;

    public static function setUpBeforeClass(): void
    {
        self::$_crypto = new OpenSSLCrypto();
        self::$_rsaPrivKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        self::$_ecPrivKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_crypto = null;
        self::$_rsaPrivKeyInfo = null;
        self::$_ecPrivKeyInfo = null;
    }

    #[Test]
    #[DataProvider('provideSignAndVerifyRSA')]
    public function signAndVerifyRSA(SignatureAlgorithmIdentifier $algo): void
    {
        $signature = self::$_crypto->sign(self::DATA, self::$_rsaPrivKeyInfo, $algo);
        static::assertInstanceOf(Signature::class, $signature);
        $pubkey_info = self::$_rsaPrivKeyInfo->publicKeyInfo();
        $result = self::$_crypto->verify(self::DATA, $signature, $pubkey_info, $algo);
        static::assertTrue($result);
    }

    public static function provideSignAndVerifyRSA(): iterable
    {
        //yield [MD4WithRSAEncryptionAlgorithmIdentifier::create()];  /** Removed as MD4 is now obsolete and fails with newer OpenSSL versions */
        yield [MD5WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [SHA1WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [SHA224WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [SHA256WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [SHA384WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [SHA512WithRSAEncryptionAlgorithmIdentifier::create()];
    }

    #[Test]
    #[DataProvider('provideSignAndVerifyEC')]
    public function signAndVerifyEC(SignatureAlgorithmIdentifier $algo): void
    {
        $signature = self::$_crypto->sign(self::DATA, self::$_ecPrivKeyInfo, $algo);
        static::assertInstanceOf(Signature::class, $signature);
        $pubkey_info = self::$_ecPrivKeyInfo->publicKeyInfo();
        $result = self::$_crypto->verify(self::DATA, $signature, $pubkey_info, $algo);
        static::assertTrue($result);
    }

    public static function provideSignAndVerifyEC(): iterable
    {
        yield [ECDSAWithSHA1AlgorithmIdentifier::create()];
    }

    #[Test]
    public function unsupportedDigestFail(): void
    {
        $algo = MD2WithRSAEncryptionAlgorithmIdentifier::create();
        $this->expectException(UnexpectedValueException::class);
        self::$_crypto->sign(self::DATA, self::$_rsaPrivKeyInfo, $algo);
    }

    #[Test]
    public function signInvalidKeyFails(): void
    {
        $pk = RSAPrivateKey::create('0', '0', '0', '0', '0', '0', '0', '0');
        $algo = SHA1WithRSAEncryptionAlgorithmIdentifier::create();
        $this->expectException(RuntimeException::class);
        self::$_crypto->sign(self::DATA, $pk->privateKeyInfo(), $algo);
    }

    #[Test]
    public function verifyInvalidKeyType(): void
    {
        $signature = RSASignature::fromSignatureString('');
        $algo = SHA1WithRSAEncryptionAlgorithmIdentifier::create();
        $pk = self::$_ecPrivKeyInfo->privateKey()->publicKey();
        $this->expectException(RuntimeException::class);
        self::$_crypto->verify(self::DATA, $signature, $pk->publicKeyInfo(), $algo);
    }

    /**
     * @param string $data
     * @param string $key
     */
    #[Test]
    #[DataProvider('provideEncryptAndDecrypt')]
    public function encryptAndDecrypt($data, CipherAlgorithmIdentifier $algo, $key): void
    {
        $ciphertext = self::$_crypto->encrypt($data, $key, $algo);
        static::assertNotSame($data, $ciphertext);
        $plaintext = self::$_crypto->decrypt($ciphertext, $key, $algo);
        static::assertSame($data, $plaintext);
    }

    public static function provideEncryptAndDecrypt(): iterable
    {
        $data8 = '12345678';
        $data16 = str_repeat($data8, 2);
        $iv8 = hex2bin('8877665544332211');
        $iv16 = str_repeat($iv8, 2);
        //$key5 = hex2bin('1122334455');
        $key8 = hex2bin('1122334455667788');
        $key16 = str_repeat($key8, 2);
        $key24 = str_repeat($key8, 3);
        $key32 = str_repeat($key16, 2);
        //yield [$data8, DESCBCAlgorithmIdentifier::create($iv8), $key8]; /** Removed as now obsolete and fails with newer OpenSSL versions */
        yield [$data8, DESEDE3CBCAlgorithmIdentifier::create($iv8), $key24];
        //yield [$data8, RC2CBCAlgorithmIdentifier::create(40, $iv8), $key5]; /** Removed as now obsolete and fails with newer OpenSSL versions */
        //yield [$data8, RC2CBCAlgorithmIdentifier::create(64, $iv8), $key8]; /** Removed as now obsolete and fails with newer OpenSSL versions */
        //yield [$data8, RC2CBCAlgorithmIdentifier::create(128, $iv8), $key16]; /** Removed as now obsolete and fails with newer OpenSSL versions */
        yield [$data16, AES128CBCAlgorithmIdentifier::create($iv16), $key16];
        yield [$data16, AES192CBCAlgorithmIdentifier::create($iv16), $key24];
        yield [$data16, AES256CBCAlgorithmIdentifier::create($iv16), $key32];
    }

    #[Test]
    public function unsupportedRC2KeySize(): void
    {
        $data = '12345678';
        $key = '12345678';
        $algo = RC2CBCAlgorithmIdentifier::create(1, '87654321');
        $this->expectException(UnexpectedValueException::class);
        self::$_crypto->encrypt($data, $key, $algo);
    }

    #[Test]
    public function encryptUnalignedFail(): void
    {
        $data = '1234567';
        $key = '12345678';
        $algo = DESCBCAlgorithmIdentifier::create('87654321');
        $this->expectException(RuntimeException::class);
        self::$_crypto->encrypt($data, $key, $algo);
    }

    #[Test]
    public function decryptUnalignedFail(): void
    {
        $data = '1234567';
        $key = '12345678';
        $algo = DESCBCAlgorithmIdentifier::create('87654321');
        $this->expectException(RuntimeException::class);
        self::$_crypto->decrypt($data, $key, $algo);
    }

    #[Test]
    public function unsupportedCipherFail(): void
    {
        $this->expectException(UnexpectedValueException::class);
        self::$_crypto->encrypt(self::DATA, '', new UnsupportedCipher());
    }

    #[Test]
    public function invalidRC2AlgoFail(): void
    {
        $this->expectException(UnexpectedValueException::class);
        self::$_crypto->encrypt(self::DATA, '', new InvalidRC2());
    }

    #[Test]
    public function unsupportedRC2KeySizeFail(): void
    {
        $this->expectException(UnexpectedValueException::class);
        self::$_crypto->encrypt(self::DATA, 'x', RC2CBCAlgorithmIdentifier::create(8, '87654321'));
    }

    #[Test]
    #[DataProvider('provideSignatureMethod')]
    public function signatureMethod(PrivateKeyInfo $pki, SignatureAlgorithmIdentifier $algo): void
    {
        $signature = self::$_crypto->sign(self::DATA, $pki, $algo);
        $result = self::$_crypto->verify(self::DATA, $signature, $pki->publicKeyInfo(), $algo);
        static::assertTrue($result);
    }

    public static function provideSignatureMethod(): iterable
    {
        $rsa_key = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $ec_key = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem'));
        //yield [$rsa_key, MD4WithRSAEncryptionAlgorithmIdentifier::create()]; /** Removed as MD4 is now obsolete and fails with newer OpenSSL versions */
        yield [$rsa_key, MD5WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [$rsa_key, SHA1WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [$rsa_key, SHA224WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [$rsa_key, SHA256WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [$rsa_key, SHA384WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [$rsa_key, SHA512WithRSAEncryptionAlgorithmIdentifier::create()];
        yield [$ec_key, ECDSAWithSHA1AlgorithmIdentifier::create()];
        yield [$ec_key, ECDSAWithSHA224AlgorithmIdentifier::create()];
        yield [$ec_key, ECDSAWithSHA256AlgorithmIdentifier::create()];
        yield [$ec_key, ECDSAWithSHA384AlgorithmIdentifier::create()];
        yield [$ec_key, ECDSAWithSHA512AlgorithmIdentifier::create()];
    }
}

class UnsupportedCipher extends CipherAlgorithmIdentifier
{
    public function __construct()
    {
        parent::__construct('1.3.6.1.3', '');
    }

    public static function create(): self
    {
        return new self();
    }

    public function name(): string
    {
        return '';
    }

    public function keySize(): int
    {
        return 1;
    }

    public function ivSize(): int
    {
        return 1;
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in derived class.');
    }

    protected function paramsASN1(): ?Element
    {
        return null;
    }
}

class InvalidRC2 extends CipherAlgorithmIdentifier
{
    public function __construct()
    {
        parent::__construct(AlgorithmIdentifier::OID_RC2_CBC, '');
    }

    public static function create(): self
    {
        return new self();
    }

    public function name(): string
    {
        return '';
    }

    public function keySize(): int
    {
        return 1;
    }

    public function ivSize(): int
    {
        return 1;
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in derived class.');
    }

    protected function paramsASN1(): ?Element
    {
        return null;
    }
}
