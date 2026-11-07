<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric;

use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES256CBCAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE\PBES2AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE\PBKDF2AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Encryption\PBES2;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Exception\InvalidPasswordException;
use function sprintf;
use Throwable;
use UnexpectedValueException;

/*
 * From RFC 5958 - 3. Encrypted Private Key Info:
 *
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *     encryptionAlgorithm EncryptionAlgorithmIdentifier,
 *     encryptedData EncryptedData
 * }
 * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier {CONTENT-ENCRYPTION, { ... }}
 * EncryptedData ::= OCTET STRING
 */

/**
 * Implements PKCS #8 EncryptedPrivateKeyInfo, the `ENCRYPTED PRIVATE KEY` PEM type.
 *
 * Decryption and encryption are supported with PBES2 (RFC 8018) using PBKDF2 with HMAC-SHA-1, -224, -256, -384 or -512
 * and AES-128/192/256-CBC, DES-EDE3-CBC or DES-CBC. PBES1, the PKCS #12 schemes and scrypt are recognised, so the
 * structure can still be read and written, but they cannot be decrypted.
 *
 * @see https://tools.ietf.org/html/rfc5958#section-3
 * @see https://tools.ietf.org/html/rfc5208#section-6
 */
final class EncryptedPrivateKeyInfo
{
    /**
     * PBKDF2 iteration count used by `encrypt()` by default.
     *
     * Fifty times the 2048 of OpenSSL 3, and about a tenth of a second with HMAC-SHA-256 in PHP on current hardware.
     * The key is decrypted whenever it is loaded, so this weighs on every load; a key that is loaded rarely can afford
     * the 600 000 the OWASP Password Storage Cheat Sheet gives for PBKDF2-HMAC-SHA256.
     *
     * @var int
     */
    public const DEFAULT_ITERATION_COUNT = 100_000;

    /**
     * Highest PBKDF2 iteration count `decrypt()` computes by default.
     *
     * The iteration count is read from the key, so without a limit a crafted key would make the caller compute as
     * much as it says, up to 2^63 iterations. This is above every recommendation that has been made for PBKDF2,
     * the highest being the 1 300 000 OWASP gives for HMAC-SHA-1, and about a thousand times the OpenSSL default,
     * while it bounds the cost of a hostile key to a few seconds of CPU: roughly 2.5 s with HMAC-SHA-1 and 4 s
     * with HMAC-SHA-512 in PHP on current hardware, where ten million would be 13 s and 20 s. A caller that trusts
     * its keys can pass a higher limit.
     *
     * @var int
     */
    public const DEFAULT_MAX_ITERATION_COUNT = 2_000_000;

    /**
     * Names of the PBES1 (RFC 8018 sect. 6.1) and PKCS #12 (RFC 7292 appendix C) schemes, to name them in the
     * error.
     *
     * @var array<string, string>
     */
    private const MAP_UNSUPPORTED_SCHEMES = [
        '1.2.840.113549.1.5.1' => 'PBES1 pbeWithMD2AndDES-CBC',
        '1.2.840.113549.1.5.4' => 'PBES1 pbeWithMD2AndRC2-CBC',
        '1.2.840.113549.1.5.3' => 'PBES1 pbeWithMD5AndDES-CBC',
        '1.2.840.113549.1.5.6' => 'PBES1 pbeWithMD5AndRC2-CBC',
        '1.2.840.113549.1.5.10' => 'PBES1 pbeWithSHA1AndDES-CBC',
        '1.2.840.113549.1.5.11' => 'PBES1 pbeWithSHA1AndRC2-CBC',
        '1.2.840.113549.1.12.1.1' => 'PKCS #12 pbeWithSHAAnd128BitRC4',
        '1.2.840.113549.1.12.1.2' => 'PKCS #12 pbeWithSHAAnd40BitRC4',
        '1.2.840.113549.1.12.1.3' => 'PKCS #12 pbeWithSHAAnd3-KeyTripleDES-CBC',
        '1.2.840.113549.1.12.1.4' => 'PKCS #12 pbeWithSHAAnd2-KeyTripleDES-CBC',
        '1.2.840.113549.1.12.1.5' => 'PKCS #12 pbeWithSHAAnd128BitRC2-CBC',
        '1.2.840.113549.1.12.1.6' => 'PKCS #12 pbewithSHAAnd40BitRC2-CBC',
    ];

    private function __construct(
        private readonly AlgorithmIdentifierType $encryptionAlgorithm,
        private readonly string $encryptedData
    ) {
    }

    public static function create(AlgorithmIdentifierType $encryptionAlgorithm, string $encryptedData): self
    {
        return new self($encryptionAlgorithm, $encryptedData);
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        if ($seq->count() !== 2) {
            throw new UnexpectedValueException('EncryptedPrivateKeyInfo must have exactly two elements.');
        }
        return self::create(
            AlgorithmIdentifier::fromASN1($seq->at(0)->asSequence()),
            $seq->at(1)
                ->asOctetString()
                ->string()
        );
    }

    /**
     * Initialize from DER data.
     */
    public static function fromDER(string $data): self
    {
        return self::fromASN1(UnspecifiedType::fromDER($data)->asSequence());
    }

    /**
     * Initialize from PEM of type `ENCRYPTED PRIVATE KEY`.
     */
    public static function fromPEM(PEM $pem): self
    {
        if ($pem->type() !== PEM::TYPE_ENCRYPTED_PRIVATE_KEY) {
            throw new UnexpectedValueException('Invalid PEM type.');
        }
        return self::fromDER($pem->data());
    }

    /**
     * Encrypt a private key with a password.
     *
     * @param OneAsymmetricKey $key Private key, a `PrivateKeyInfo` or a `OneAsymmetricKey`
     * @param null|PBES2AlgorithmIdentifier $algo Encryption parameters, `defaultEncryptionAlgorithm()` if null. The
     * salt and the IV in them must not be reused for another encryption.
     */
    public static function encrypt(
        OneAsymmetricKey $key,
        string $password,
        ?PBES2AlgorithmIdentifier $algo = null,
        ?Crypto $crypto = null
    ): self {
        $algo ??= self::defaultEncryptionAlgorithm();
        $crypto ??= Crypto::getDefault();
        return self::create($algo, PBES2::encrypt($key->toDER(), $password, $algo, $crypto));
    }

    /**
     * Get PBES2 parameters with a fresh random 16 byte salt and IV: PBKDF2 with HMAC-SHA-256 and AES-256-CBC, the
     * default of OpenSSL 3.
     *
     * @param int $iterationCount PBKDF2 iteration count
     */
    public static function defaultEncryptionAlgorithm(
        int $iterationCount = self::DEFAULT_ITERATION_COUNT
    ): PBES2AlgorithmIdentifier {
        return PBES2AlgorithmIdentifier::create(
            PBKDF2AlgorithmIdentifier::create(
                random_bytes(16),
                $iterationCount,
                null,
                HMACWithSHA256AlgorithmIdentifier::create(NullType::create())
            ),
            AES256CBCAlgorithmIdentifier::create(random_bytes(16))
        );
    }

    public function encryptionAlgorithm(): AlgorithmIdentifierType
    {
        return $this->encryptionAlgorithm;
    }

    public function encryptedData(): string
    {
        return $this->encryptedData;
    }

    /**
     * Decrypt the private key.
     *
     * @param int $maxIterationCount Highest PBKDF2 iteration count to compute, see `DEFAULT_MAX_ITERATION_COUNT`
     *
     * @throws InvalidPasswordException If the password is wrong, or the encrypted data was damaged
     * @throws UnexpectedValueException If the algorithm is not supported or the structure is not valid
     */
    public function decrypt(
        string $password,
        ?Crypto $crypto = null,
        int $maxIterationCount = self::DEFAULT_MAX_ITERATION_COUNT
    ): PrivateKeyInfo {
        $algo = $this->encryptionAlgorithm;
        if (! $algo instanceof PBES2AlgorithmIdentifier) {
            throw new UnexpectedValueException(sprintf(
                'Encryption scheme %s is not supported, only PBES2 is.',
                self::MAP_UNSUPPORTED_SCHEMES[$algo->oid()] ?? $algo->name()
            ));
        }
        $crypto ??= Crypto::getDefault();
        $der = PBES2::decrypt($this->encryptedData, $password, $algo, $crypto, $maxIterationCount);
        try {
            return PrivateKeyInfo::fromDER($der);
        } catch (Throwable $e) {
            // padding that happens to look valid is not rare enough under a wrong key, about one in 256
            throw new InvalidPasswordException('Invalid password or corrupted data.', 0, $e);
        }
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return Sequence::create($this->encryptionAlgorithm->toASN1(), OctetString::create($this->encryptedData));
    }

    /**
     * Generate DER encoding.
     */
    public function toDER(): string
    {
        return $this->toASN1()
            ->toDER();
    }

    /**
     * Generate PEM.
     */
    public function toPEM(): PEM
    {
        return PEM::create(PEM::TYPE_ENCRYPTED_PRIVATE_KEY, $this->toDER());
    }
}
