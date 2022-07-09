<?php

declare(strict_types = 1);

namespace Sop\CryptoBridge;

use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Signature\Signature;

/**
 * Base class for crypto engine implementations.
 */
abstract class Crypto
{
    /**
     * Sign data with given algorithm using given private key.
     *
     * @param string                       $data         Data to sign
     * @param PrivateKeyInfo               $privkey_info Private key
     * @param SignatureAlgorithmIdentifier $algo         Signature algorithm
     *
     * @return Signature
     */
    abstract public function sign(string $data, PrivateKeyInfo $privkey_info,
        SignatureAlgorithmIdentifier $algo): Signature;

    /**
     * Verify signature with given algorithm using given public key.
     *
     * @param string                       $data        Data to verify
     * @param Signature                    $signature   Signature
     * @param PublicKeyInfo                $pubkey_info Public key
     * @param SignatureAlgorithmIdentifier $algo        Signature algorithm
     *
     * @return bool True if signature matches
     */
    abstract public function verify(string $data, Signature $signature,
        PublicKeyInfo $pubkey_info, SignatureAlgorithmIdentifier $algo): bool;

    /**
     * Encrypt data with given algorithm using given key.
     *
     * Padding must be added by the caller. Initialization vector is
     * taken from the algorithm identifier if available.
     *
     * @param string                    $data Plaintext
     * @param string                    $key  Encryption key
     * @param CipherAlgorithmIdentifier $algo Encryption algorithm
     *
     * @return string Ciphertext
     */
    abstract public function encrypt(string $data, string $key,
        CipherAlgorithmIdentifier $algo): string;

    /**
     * Decrypt data with given algorithm using given key.
     *
     * Possible padding is not removed and must be handled by the caller.
     * Initialization vector is taken from the algorithm identifier if
     * available.
     *
     * @param string                    $data Ciphertext
     * @param string                    $key  Encryption key
     * @param CipherAlgorithmIdentifier $algo Encryption algorithm
     *
     * @return string Plaintext
     */
    abstract public function decrypt(string $data, string $key,
        CipherAlgorithmIdentifier $algo): string;

    /**
     * Get default supported crypto implementation.
     *
     * @return self
     */
    public static function getDefault(): self
    {
        if (defined('OPENSSL_VERSION_NUMBER')) {
            return new Crypto\OpenSSLCrypto();
        }
        // @codeCoverageIgnoreStart
        throw new \RuntimeException('No crypto implementation available.');
        // @codeCoverageIgnoreEnd
    }
}
