<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric;

use function in_array;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Attribute\OneAsymmetricKeyAttributes;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Encryption\LegacyPEMEncryption;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Exception\InvalidPasswordException;
use function sprintf;
use Throwable;
use UnexpectedValueException;

/**
 * PrivateKeyInfo was first introduced in RFC 5208, but later refined as OneAsymmetricKey in RFC 5958 with backwards
 * compatibility.
 *
 * Thus `PrivateKeyInfo ::= OneAsymmetricKey`
 *
 * @see https://tools.ietf.org/html/rfc5208#section-5
 * @see https://tools.ietf.org/html/rfc5958#section-2
 */
final class PrivateKeyInfo extends OneAsymmetricKey
{
    // PrivateKeyInfo has version 1 by default
    public static function create(
        AlgorithmIdentifierType $algo,
        string $key,
        ?OneAsymmetricKeyAttributes $attributes = null,
        ?BitString $public_key = null,
    ): self {
        return new self($algo, $key, $attributes, $public_key, parent::VERSION_1);
    }

    /**
     * Initialize from a password protected PEM.
     *
     * Two forms are accepted: PKCS #8 `ENCRYPTED PRIVATE KEY` (`EncryptedPrivateKeyInfo`), which is what `openssl
     * genpkey -aes256` and `openssl pkcs8 -topk8` write, and the traditional OpenSSL form of an RSA or EC key with a
     * `Proc-Type: 4,ENCRYPTED` header (`LegacyPEMEncryption`). A PEM that is not encrypted is refused, so that a
     * password that is expected to protect a key is never silently ignored: use `fromPEM()` for those.
     *
     * @param int $maxIterationCount Highest PBKDF2 iteration count to compute, see
     * `EncryptedPrivateKeyInfo::DEFAULT_MAX_ITERATION_COUNT`
     *
     * @throws InvalidPasswordException If the password is wrong, or the encrypted data was damaged
     * @throws UnexpectedValueException If the PEM is not encrypted, or not in a supported way
     */
    public static function fromEncryptedPEM(
        PEM $pem,
        string $password,
        ?Crypto $crypto = null,
        int $maxIterationCount = EncryptedPrivateKeyInfo::DEFAULT_MAX_ITERATION_COUNT
    ): self {
        if ($pem->type() === PEM::TYPE_ENCRYPTED_PRIVATE_KEY) {
            return EncryptedPrivateKeyInfo::fromPEM($pem)->decrypt($password, $crypto, $maxIterationCount);
        }
        if ($pem->isEncrypted()) {
            if (! in_array($pem->type(), [PEM::TYPE_RSA_PRIVATE_KEY, PEM::TYPE_EC_PRIVATE_KEY], true)) {
                throw new UnexpectedValueException(sprintf(
                    'Encrypted PEM type %s is not supported, only %s and %s are.',
                    $pem->type(),
                    PEM::TYPE_RSA_PRIVATE_KEY,
                    PEM::TYPE_EC_PRIVATE_KEY
                ));
            }
            $decrypted = LegacyPEMEncryption::decrypt($pem, $password, $crypto);
            try {
                return self::fromPrivateKey(PrivateKey::fromPEM($decrypted));
            } catch (Throwable $e) {
                // a DER SEQUENCE alone does not prove the password, it must also be a key of the stated type
                throw new InvalidPasswordException('Invalid password or corrupted data.', 0, $e);
            }
        }
        throw new UnexpectedValueException('PEM is not encrypted.');
    }
}
