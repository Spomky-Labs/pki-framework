<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher;

use function mb_strlen;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * Base class for cipher algorithm identifiers.
 */
abstract class CipherAlgorithmIdentifier extends SpecificAlgorithmIdentifier
{
    /**
     * Initialization vector.
     *
     * @var null|string
     */
    protected $_initializationVector;

    /**
     * Get key size in bytes.
     */
    abstract public function keySize(): int;

    /**
     * Get the initialization vector size in bytes.
     */
    abstract public function ivSize(): int;

    /**
     * Get initialization vector.
     */
    public function initializationVector(): ?string
    {
        return $this->_initializationVector;
    }

    /**
     * Get copy of the object with given initialization vector.
     *
     * @param null|string $iv Initialization vector or null to remove
     */
    public function withInitializationVector(?string $iv): self
    {
        $this->_checkIVSize($iv);
        $obj = clone $this;
        $obj->_initializationVector = $iv;
        return $obj;
    }

    /**
     * Check that initialization vector size is valid for the cipher.
     */
    protected function _checkIVSize(?string $iv): void
    {
        if ($iv !== null && mb_strlen($iv, '8bit') !== $this->ivSize()) {
            throw new UnexpectedValueException('Invalid IV size.');
        }
    }
}
