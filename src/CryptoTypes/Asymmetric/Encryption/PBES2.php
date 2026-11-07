<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\Encryption;

use function array_key_exists;
use function in_array;
use function mb_strlen;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Exception\InvalidPasswordException;
use function sprintf;
use UnexpectedValueException;

/**
 * PBES2 encryption and decryption with PBKDF2 (RFC 8018 sect. 5.2 and 6.2).
 *
 * @internal
 */
final class PBES2
{
    /**
     * The PBKDF2 pseudorandom functions supported, by OID, with the name hash_pbkdf2() knows their hash by.
     *
     * @var array<string, string>
     */
    private const MAP_PRF_OID_TO_HASH = [
        AlgorithmIdentifier::OID_HMAC_WITH_SHA1 => 'sha1',
        AlgorithmIdentifier::OID_HMAC_WITH_SHA224 => 'sha224',
        AlgorithmIdentifier::OID_HMAC_WITH_SHA256 => 'sha256',
        AlgorithmIdentifier::OID_HMAC_WITH_SHA384 => 'sha384',
        AlgorithmIdentifier::OID_HMAC_WITH_SHA512 => 'sha512',
    ];

    /**
     * The ciphers supported for the encryption scheme.
     *
     * @var string[]
     */
    private const CIPHER_OIDS = [
        AlgorithmIdentifier::OID_AES_128_CBC,
        AlgorithmIdentifier::OID_AES_192_CBC,
        AlgorithmIdentifier::OID_AES_256_CBC,
        AlgorithmIdentifier::OID_DES_EDE3_CBC,
        AlgorithmIdentifier::OID_DES_CBC,
    ];

    /**
     * Names of key derivation functions known not to be supported, to name them in the error.
     *
     * @var array<string, string>
     */
    private const MAP_UNSUPPORTED_KDF = [
        // RFC 7914 sect. 7, there is no scrypt in PHP itself
        '1.3.6.1.4.1.11591.4.11' => 'scrypt',
    ];

    public static function encrypt(
        string $data,
        string $password,
        PBES2AlgorithmIdentifier $algo,
        Crypto $crypto
    ): string {
        $cipher = self::cipher($algo);
        $key = self::deriveKey($algo, $cipher, $password, null);
        return $crypto->encrypt(PKCS7Padding::add($data, $cipher->blockSize()), $key, $cipher);
    }

    /**
     * Decrypt and remove the padding.
     *
     * @param int $maxIterationCount Highest PBKDF2 iteration count to compute
     */
    public static function decrypt(
        string $data,
        string $password,
        PBES2AlgorithmIdentifier $algo,
        Crypto $crypto,
        int $maxIterationCount
    ): string {
        $cipher = self::cipher($algo);
        $length = mb_strlen($data, '8bit');
        if ($length === 0 || $length % $cipher->blockSize() !== 0) {
            throw new UnexpectedValueException(sprintf(
                'Encrypted data length %d is not a positive multiple of the %s block size.',
                $length,
                $cipher->name()
            ));
        }
        $key = self::deriveKey($algo, $cipher, $password, $maxIterationCount);
        $plaintext = PKCS7Padding::remove($crypto->decrypt($data, $key, $cipher), $cipher->blockSize());
        if ($plaintext === null) {
            throw new InvalidPasswordException('Invalid password or corrupted data.');
        }
        return $plaintext;
    }

    /**
     * Derive the encryption key with PBKDF2.
     *
     * @param null|int $maxIterationCount Highest iteration count to compute, null for no limit
     */
    private static function deriveKey(
        PBES2AlgorithmIdentifier $algo,
        BlockCipherAlgorithmIdentifier $cipher,
        string $password,
        ?int $maxIterationCount
    ): string {
        $kdf = $algo->keyDerivationFunc();
        if (! $kdf instanceof PBKDF2AlgorithmIdentifier) {
            throw new UnexpectedValueException(sprintf(
                'PBES2 key derivation function %s is not supported.',
                self::MAP_UNSUPPORTED_KDF[$kdf->oid()] ?? $kdf->name()
            ));
        }
        $prf = $kdf->prf();
        if (! array_key_exists($prf->oid(), self::MAP_PRF_OID_TO_HASH)) {
            throw new UnexpectedValueException(sprintf(
                'PBKDF2 pseudorandom function %s is not supported.',
                $prf->name()
            ));
        }
        $keySize = $cipher->keySize();
        if ($keySize < 1) {
            throw new UnexpectedValueException(sprintf('Invalid key size for %s.', $cipher->name()));
        }
        if ($kdf->keyLength() !== null && $kdf->keyLength() !== $keySize) {
            throw new UnexpectedValueException(sprintf(
                'PBKDF2 key length %d does not match the %d byte key of %s.',
                $kdf->keyLength(),
                $keySize,
                $cipher->name()
            ));
        }
        if ($maxIterationCount !== null && $kdf->iterationCount() > $maxIterationCount) {
            throw new UnexpectedValueException(sprintf(
                'PBKDF2 iteration count %d exceeds the maximum of %d.',
                $kdf->iterationCount(),
                $maxIterationCount
            ));
        }
        return hash_pbkdf2(
            self::MAP_PRF_OID_TO_HASH[$prf->oid()],
            $password,
            $kdf->salt(),
            $kdf->iterationCount(),
            $keySize,
            true
        );
    }

    private static function cipher(PBES2AlgorithmIdentifier $algo): BlockCipherAlgorithmIdentifier
    {
        $cipher = $algo->encryptionScheme();
        if (! $cipher instanceof BlockCipherAlgorithmIdentifier || ! in_array(
            $cipher->oid(),
            self::CIPHER_OIDS,
            true
        )) {
            throw new UnexpectedValueException(sprintf(
                'PBES2 encryption scheme %s is not supported.',
                $cipher->name()
            ));
        }
        return $cipher;
    }
}
