<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\Exception;

use UnexpectedValueException;

/**
 * Thrown when an encrypted private key does not decrypt with the given password.
 *
 * A wrong password is recognised by what it produces: padding that is not PKCS #7 or a plaintext that is not the
 * expected DER structure. A ciphertext damaged after it was written cannot be told apart from that and is reported
 * the same way, while a damaged envelope around it, an unsupported algorithm or a ciphertext of an impossible length
 * is reported as a plain `UnexpectedValueException`.
 */
final class InvalidPasswordException extends UnexpectedValueException
{
}
