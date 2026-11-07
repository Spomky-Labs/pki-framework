<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\PBE;

use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use UnexpectedValueException;

/*
 * From RFC 8018 - A.4. PBES2:
 *
 * PBES2-params ::= SEQUENCE {
 *     keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
 *     encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
 * }
 */

/**
 * Algorithm identifier for the PBES2 password-based encryption scheme.
 *
 * Both components are kept as whatever algorithm identifier they name, so that a structure using a key derivation
 * function or a cipher this library cannot compute, scrypt for instance, still parses and re-encodes. Whether it can
 * be decrypted is decided when it is.
 *
 * @see https://tools.ietf.org/html/rfc8018#section-6.2
 * @see https://tools.ietf.org/html/rfc8018#appendix-A.4
 */
final class PBES2AlgorithmIdentifier extends SpecificAlgorithmIdentifier
{
    private function __construct(
        private readonly AlgorithmIdentifierType $keyDerivationFunc,
        private readonly AlgorithmIdentifierType $encryptionScheme
    ) {
        parent::__construct(self::OID_PBES2);
    }

    /**
     * @param AlgorithmIdentifierType $keyDerivationFunc Key derivation function, PBKDF2 being the one supported
     * @param AlgorithmIdentifierType $encryptionScheme Cipher, with its initialization vector
     */
    public static function create(
        AlgorithmIdentifierType $keyDerivationFunc,
        AlgorithmIdentifierType $encryptionScheme
    ): self {
        return new self($keyDerivationFunc, $encryptionScheme);
    }

    public function name(): string
    {
        return 'PBES2';
    }

    /**
     * @return self
     */
    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        if (! isset($params)) {
            throw new UnexpectedValueException('No parameters.');
        }
        $seq = $params->asSequence();
        if ($seq->count() !== 2) {
            throw new UnexpectedValueException('PBES2 parameters must have exactly two elements.');
        }
        return self::create(
            AlgorithmIdentifier::fromASN1($seq->at(0)->asSequence()),
            AlgorithmIdentifier::fromASN1($seq->at(1)->asSequence())
        );
    }

    public function keyDerivationFunc(): AlgorithmIdentifierType
    {
        return $this->keyDerivationFunc;
    }

    public function encryptionScheme(): AlgorithmIdentifierType
    {
        return $this->encryptionScheme;
    }

    protected function paramsASN1(): Sequence
    {
        return Sequence::create($this->keyDerivationFunc->toASN1(), $this->encryptionScheme->toASN1());
    }
}
