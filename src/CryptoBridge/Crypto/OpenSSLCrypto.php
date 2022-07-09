<?php

declare(strict_types = 1);

namespace Sop\CryptoBridge\Crypto;

use Sop\CryptoBridge\Crypto;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Signature\Signature;

/**
 * Crypto engine using OpenSSL extension.
 */
class OpenSSLCrypto extends Crypto
{
    /**
     * Mapping from algorithm OID to OpenSSL signature method identifier.
     *
     * @internal
     *
     * @var array
     */
    const MAP_DIGEST_OID = [
        AlgorithmIdentifier::OID_MD4_WITH_RSA_ENCRYPTION => OPENSSL_ALGO_MD4,
        AlgorithmIdentifier::OID_MD5_WITH_RSA_ENCRYPTION => OPENSSL_ALGO_MD5,
        AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION => OPENSSL_ALGO_SHA1,
        AlgorithmIdentifier::OID_SHA224_WITH_RSA_ENCRYPTION => OPENSSL_ALGO_SHA224,
        AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION => OPENSSL_ALGO_SHA256,
        AlgorithmIdentifier::OID_SHA384_WITH_RSA_ENCRYPTION => OPENSSL_ALGO_SHA384,
        AlgorithmIdentifier::OID_SHA512_WITH_RSA_ENCRYPTION => OPENSSL_ALGO_SHA512,
        AlgorithmIdentifier::OID_ECDSA_WITH_SHA1 => OPENSSL_ALGO_SHA1,
        AlgorithmIdentifier::OID_ECDSA_WITH_SHA224 => OPENSSL_ALGO_SHA224,
        AlgorithmIdentifier::OID_ECDSA_WITH_SHA256 => OPENSSL_ALGO_SHA256,
        AlgorithmIdentifier::OID_ECDSA_WITH_SHA384 => OPENSSL_ALGO_SHA384,
        AlgorithmIdentifier::OID_ECDSA_WITH_SHA512 => OPENSSL_ALGO_SHA512,
    ];

    /**
     * Mapping from algorithm OID to OpenSSL cipher method name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_CIPHER_OID = [
        AlgorithmIdentifier::OID_DES_CBC => 'des-cbc',
        AlgorithmIdentifier::OID_DES_EDE3_CBC => 'des-ede3-cbc',
        AlgorithmIdentifier::OID_AES_128_CBC => 'aes-128-cbc',
        AlgorithmIdentifier::OID_AES_192_CBC => 'aes-192-cbc',
        AlgorithmIdentifier::OID_AES_256_CBC => 'aes-256-cbc',
    ];

    /**
     * {@inheritdoc}
     */
    public function sign(string $data, PrivateKeyInfo $privkey_info,
        SignatureAlgorithmIdentifier $algo): Signature
    {
        $this->_checkSignatureAlgoAndKey($algo, $privkey_info->algorithmIdentifier());
        $result = openssl_sign($data, $signature, $privkey_info->toPEM(),
            $this->_algoToDigest($algo));
        if (false === $result) {
            throw new \RuntimeException('openssl_sign() failed: ' .
                $this->_getLastError());
        }
        return Signature::fromSignatureData($signature, $algo);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $data, Signature $signature,
        PublicKeyInfo $pubkey_info, SignatureAlgorithmIdentifier $algo): bool
    {
        $this->_checkSignatureAlgoAndKey($algo, $pubkey_info->algorithmIdentifier());
        $result = openssl_verify($data, $signature->bitString()->string(),
            $pubkey_info->toPEM(), $this->_algoToDigest($algo));
        if (-1 == $result) {
            throw new \RuntimeException('openssl_verify() failed: ' .
                $this->_getLastError());
        }
        return 1 == $result ? true : false;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(string $data, string $key,
        CipherAlgorithmIdentifier $algo): string
    {
        $this->_checkCipherKeySize($algo, $key);
        $iv = $algo->initializationVector();
        $result = openssl_encrypt($data, $this->_algoToCipher($algo), $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if (false === $result) {
            throw new \RuntimeException('openssl_encrypt() failed: ' .
                $this->_getLastError());
        }
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $data, string $key,
        CipherAlgorithmIdentifier $algo): string
    {
        $this->_checkCipherKeySize($algo, $key);
        $iv = $algo->initializationVector();
        $result = openssl_decrypt($data, $this->_algoToCipher($algo), $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if (false === $result) {
            throw new \RuntimeException('openssl_decrypt() failed: ' .
                $this->_getLastError());
        }
        return $result;
    }

    /**
     * Validate cipher algorithm key size.
     *
     * @param CipherAlgorithmIdentifier $algo
     * @param string                    $key
     *
     * @throws \UnexpectedValueException
     */
    protected function _checkCipherKeySize(CipherAlgorithmIdentifier $algo, string $key): void
    {
        if ($algo instanceof BlockCipherAlgorithmIdentifier) {
            if (strlen($key) !== $algo->keySize()) {
                throw new \UnexpectedValueException(
                    sprintf('Key length for %s must be %d, %d given.',
                        $algo->name(), $algo->keySize(), strlen($key)));
            }
        }
    }

    /**
     * Get last OpenSSL error message.
     *
     * @return null|string
     */
    protected function _getLastError(): ?string
    {
        // pump error message queue
        $msg = null;
        while (false !== ($err = openssl_error_string())) {
            $msg = $err;
        }
        return $msg;
    }

    /**
     * Check that given signature algorithm supports key of given type.
     *
     * @param SignatureAlgorithmIdentifier $sig_algo Signature algorithm
     * @param AlgorithmIdentifier          $key_algo Key algorithm
     *
     * @throws \UnexpectedValueException If key is not supported
     */
    protected function _checkSignatureAlgoAndKey(
        SignatureAlgorithmIdentifier $sig_algo,
        AlgorithmIdentifier $key_algo): void
    {
        if (!$sig_algo->supportsKeyAlgorithm($key_algo)) {
            throw new \UnexpectedValueException(
                sprintf('Signature algorithm %s does not support key algorithm %s.',
                    $sig_algo->name(), $key_algo->name()));
        }
    }

    /**
     * Get OpenSSL digest method for given signature algorithm identifier.
     *
     * @param SignatureAlgorithmIdentifier $algo
     *
     * @throws \UnexpectedValueException If digest method is not supported
     *
     * @return int
     */
    protected function _algoToDigest(SignatureAlgorithmIdentifier $algo): int
    {
        $oid = $algo->oid();
        if (!array_key_exists($oid, self::MAP_DIGEST_OID)) {
            throw new \UnexpectedValueException(
                sprintf('Digest method %s not supported.', $algo->name()));
        }
        return self::MAP_DIGEST_OID[$oid];
    }

    /**
     * Get OpenSSL cipher method for given cipher algorithm identifier.
     *
     * @param CipherAlgorithmIdentifier $algo
     *
     * @throws \UnexpectedValueException If cipher method is not supported
     *
     * @return string
     */
    protected function _algoToCipher(CipherAlgorithmIdentifier $algo): string
    {
        $oid = $algo->oid();
        if (array_key_exists($oid, self::MAP_CIPHER_OID)) {
            return self::MAP_CIPHER_OID[$oid];
        }
        if (AlgorithmIdentifier::OID_RC2_CBC === $oid) {
            if (!$algo instanceof RC2CBCAlgorithmIdentifier) {
                throw new \UnexpectedValueException('Not an RC2-CBC algorithm.');
            }
            return $this->_rc2AlgoToCipher($algo);
        }
        throw new \UnexpectedValueException(
            sprintf('Cipher method %s not supported.', $algo->name()));
    }

    /**
     * Get OpenSSL cipher method for given RC2 algorithm identifier.
     *
     * @param RC2CBCAlgorithmIdentifier $algo
     *
     * @throws \UnexpectedValueException If cipher's key size is not supported
     *
     * @return string
     */
    protected function _rc2AlgoToCipher(RC2CBCAlgorithmIdentifier $algo): string
    {
        switch ($algo->effectiveKeyBits()) {
            case 128:
                return 'rc2-cbc';
            case 64:
                return 'rc2-64-cbc';
            case 40:
                return 'rc2-40-cbc';
        }
        throw new \UnexpectedValueException(
            $algo->effectiveKeyBits() . ' bit RC2 not supported.');
    }
}
