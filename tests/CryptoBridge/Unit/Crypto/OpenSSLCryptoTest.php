<?php

declare(strict_types=1);

namespace Sop\Test\CryptoBridge\Unit\Crypto;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\CryptoBridge\Crypto\OpenSSLCrypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\AES128CBCAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\AES192CBCAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\AES256CBCAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA224AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA384AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA512AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\MD2WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\MD4WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\MD5WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA224WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA384WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use Sop\CryptoTypes\Signature\RSASignature;
use Sop\CryptoTypes\Signature\Signature;

/**
 * @group crypto
 * @requires extension openssl
 *
 * @internal
 */
class OpenSSLCryptoTest extends TestCase
{
    public const DATA = 'PAYLOAD';

    /**
     * @var OpenSSLCrypto
     */
    private static $_crypto;

    /**
     * @var PrivateKeyInfo
     */
    private static $_rsaPrivKeyInfo;

    /**
     * @var PrivateKeyInfo
     */
    private static $_ecPrivKeyInfo;

    public static function setUpBeforeClass(): void
    {
        self::$_crypto = new OpenSSLCrypto();
        self::$_rsaPrivKeyInfo = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem')
        );
        self::$_ecPrivKeyInfo = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem')
        );
    }

    public static function tearDownAfterClass(): void
    {
        self::$_crypto = null;
        self::$_rsaPrivKeyInfo = null;
        self::$_ecPrivKeyInfo = null;
    }

    /**
     * @dataProvider provideSignAndVerifyRSA
     */
    public function testSignAndVerifyRSA(SignatureAlgorithmIdentifier $algo)
    {
        $signature = self::$_crypto->sign(
            self::DATA,
            self::$_rsaPrivKeyInfo,
            $algo
        );
        $this->assertInstanceOf(Signature::class, $signature);
        $pubkey_info = self::$_rsaPrivKeyInfo->publicKeyInfo();
        $result = self::$_crypto->verify(
            self::DATA,
            $signature,
            $pubkey_info,
            $algo
        );
        $this->assertTrue($result);
    }

    /**
     * @return SignatureAlgorithmIdentifier[]
     */
    public function provideSignAndVerifyRSA()
    {
        return [
            [new MD4WithRSAEncryptionAlgorithmIdentifier()],
            [new MD5WithRSAEncryptionAlgorithmIdentifier()],
            [new SHA1WithRSAEncryptionAlgorithmIdentifier()],
            [new SHA224WithRSAEncryptionAlgorithmIdentifier()],
            [new SHA256WithRSAEncryptionAlgorithmIdentifier()],
            [new SHA384WithRSAEncryptionAlgorithmIdentifier()],
            [new SHA512WithRSAEncryptionAlgorithmIdentifier()],
        ];
    }

    /**
     * @dataProvider provideSignAndVerifyEC
     */
    public function testSignAndVerifyEC(SignatureAlgorithmIdentifier $algo)
    {
        $signature = self::$_crypto->sign(
            self::DATA,
            self::$_ecPrivKeyInfo,
            $algo
        );
        $this->assertInstanceOf(Signature::class, $signature);
        $pubkey_info = self::$_ecPrivKeyInfo->publicKeyInfo();
        $result = self::$_crypto->verify(
            self::DATA,
            $signature,
            $pubkey_info,
            $algo
        );
        $this->assertTrue($result);
    }

    /**
     * @return SignatureAlgorithmIdentifier[][]
     */
    public function provideSignAndVerifyEC()
    {
        return [
            [new ECDSAWithSHA1AlgorithmIdentifier()],
        ];
    }

    public function testUnsupportedDigestFail()
    {
        $algo = new MD2WithRSAEncryptionAlgorithmIdentifier();
        $this->expectException(\UnexpectedValueException::class);
        self::$_crypto->sign(self::DATA, self::$_rsaPrivKeyInfo, $algo);
    }

    public function testSignInvalidKeyFails()
    {
        $pk = new RSAPrivateKey(0, 0, 0, 0, 0, 0, 0, 0);
        $algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
        $this->expectException(\RuntimeException::class);
        self::$_crypto->sign(self::DATA, $pk->privateKeyInfo(), $algo);
    }

    public function testVerifyBrokenAlgoInvalidKeyType()
    {
        $signature = RSASignature::fromSignatureString('');
        $algo = new OpenSSLCryptoTest_SHA1WithRSAAsEC();
        $pk = self::$_ecPrivKeyInfo->privateKey()->publicKey();
        $this->expectException(\RuntimeException::class);
        self::$_crypto->verify(
            self::DATA,
            $signature,
            $pk->publicKeyInfo(),
            $algo
        );
    }

    public function testVerifyInvalidKeyType()
    {
        $signature = RSASignature::fromSignatureString('');
        $algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
        $pk = self::$_ecPrivKeyInfo->privateKey()->publicKey();
        $this->expectException(\RuntimeException::class);
        self::$_crypto->verify(
            self::DATA,
            $signature,
            $pk->publicKeyInfo(),
            $algo
        );
    }

    /**
     * @dataProvider provideEncryptAndDecrypt
     *
     * @param string $data
     * @param string $key
     */
    public function testEncryptAndDecrypt(
        $data,
        CipherAlgorithmIdentifier $algo,
        $key
    ) {
        $ciphertext = self::$_crypto->encrypt($data, $key, $algo);
        $this->assertNotEquals($data, $ciphertext);
        $plaintext = self::$_crypto->decrypt($ciphertext, $key, $algo);
        $this->assertEquals($data, $plaintext);
    }

    /**
     * @return CipherAlgorithmIdentifier[]
     */
    public function provideEncryptAndDecrypt()
    {
        $data8 = '12345678';
        $data16 = str_repeat($data8, 2);
        $iv8 = hex2bin('8877665544332211');
        $iv16 = str_repeat($iv8, 2);
        $key5 = hex2bin('1122334455');
        $key8 = hex2bin('1122334455667788');
        $key16 = str_repeat($key8, 2);
        $key24 = str_repeat($key8, 3);
        $key32 = str_repeat($key16, 2);
        return [
            [$data8, new DESCBCAlgorithmIdentifier($iv8), $key8],
            [$data8, new DESEDE3CBCAlgorithmIdentifier($iv8), $key24],
            [$data8, new RC2CBCAlgorithmIdentifier(40, $iv8), $key5],
            [$data8, new RC2CBCAlgorithmIdentifier(64, $iv8), $key8],
            [$data8, new RC2CBCAlgorithmIdentifier(128, $iv8), $key16],
            [$data16, new AES128CBCAlgorithmIdentifier($iv16), $key16],
            [$data16, new AES192CBCAlgorithmIdentifier($iv16), $key24],
            [$data16, new AES256CBCAlgorithmIdentifier($iv16), $key32],
        ];
    }

    public function testUnsupportedRC2KeySize()
    {
        $data = '12345678';
        $key = '12345678';
        $algo = new RC2CBCAlgorithmIdentifier(1, '87654321');
        $this->expectException(\UnexpectedValueException::class);
        self::$_crypto->encrypt($data, $key, $algo);
    }

    public function testEncryptUnalignedFail()
    {
        $data = '1234567';
        $key = '12345678';
        $algo = new DESCBCAlgorithmIdentifier('87654321');
        $this->expectException(\RuntimeException::class);
        self::$_crypto->encrypt($data, $key, $algo);
    }

    public function testDecryptUnalignedFail()
    {
        $data = '1234567';
        $key = '12345678';
        $algo = new DESCBCAlgorithmIdentifier('87654321');
        $this->expectException(\RuntimeException::class);
        self::$_crypto->decrypt($data, $key, $algo);
    }

    public function testUnsupportedCipherFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        self::$_crypto->encrypt(
            self::DATA,
            '',
            new OpenSSLCryptoTest_UnsupportedCipher()
        );
    }

    public function testInvalidRC2AlgoFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        self::$_crypto->encrypt(
            self::DATA,
            '',
            new OpenSSLCryptoTest_InvalidRC2()
        );
    }

    public function testUnsupportedRC2KeySizeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        self::$_crypto->encrypt(
            self::DATA,
            'x',
            new RC2CBCAlgorithmIdentifier(8, '87654321')
        );
    }

    /**
     * @dataProvider provideSignatureMethod
     */
    public function testSignatureMethod(
        PrivateKeyInfo $pki,
        SignatureAlgorithmIdentifier $algo
    ) {
        $signature = self::$_crypto->sign(self::DATA, $pki, $algo);
        $result = self::$_crypto->verify(
            self::DATA,
            $signature,
            $pki->publicKeyInfo(),
            $algo
        );
        $this->assertTrue($result);
    }

    /**
     * @return SignatureAlgorithmIdentifier[]
     */
    public function provideSignatureMethod()
    {
        $rsa_key = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem')
        );
        $ec_key = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem')
        );
        return [
            [$rsa_key, new MD4WithRSAEncryptionAlgorithmIdentifier()],
            [$rsa_key, new MD5WithRSAEncryptionAlgorithmIdentifier()],
            [$rsa_key, new SHA1WithRSAEncryptionAlgorithmIdentifier()],
            [$rsa_key, new SHA224WithRSAEncryptionAlgorithmIdentifier()],
            [$rsa_key, new SHA256WithRSAEncryptionAlgorithmIdentifier()],
            [$rsa_key, new SHA384WithRSAEncryptionAlgorithmIdentifier()],
            [$rsa_key, new SHA512WithRSAEncryptionAlgorithmIdentifier()],
            [$ec_key, new ECDSAWithSHA1AlgorithmIdentifier()],
            [$ec_key, new ECDSAWithSHA224AlgorithmIdentifier()],
            [$ec_key, new ECDSAWithSHA256AlgorithmIdentifier()],
            [$ec_key, new ECDSAWithSHA384AlgorithmIdentifier()],
            [$ec_key, new ECDSAWithSHA512AlgorithmIdentifier()],
        ];
    }
}

class OpenSSLCryptoTest_SHA1WithRSAAsEC extends SHA1WithRSAEncryptionAlgorithmIdentifier
{
    public function supportsKeyAlgorithm(AlgorithmIdentifier $algo): bool
    {
        return true;
    }
}

class OpenSSLCryptoTest_UnsupportedCipher extends CipherAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = '1.3.6.1.3';
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

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}

class OpenSSLCryptoTest_InvalidRC2 extends CipherAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = AlgorithmIdentifier::OID_RC2_CBC;
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

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}
