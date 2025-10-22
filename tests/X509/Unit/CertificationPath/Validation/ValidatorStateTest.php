<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath\Validation;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\ValidatorState;

/**
 * @internal
 */
final class ValidatorStateTest extends TestCase
{
    private static ?Certificate $_ca = null;

    public static function setUpBeforeClass(): void
    {
        self::$_ca = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_ca = null;
    }

    #[Test]
    public function initialize(): ValidatorState
    {
        $state = ValidatorState::initialize(PathValidationConfig::defaultConfig(), self::$_ca, 3);
        static::assertInstanceOf(ValidatorState::class, $state);
        return $state;
    }

    #[Test]
    #[Depends('initialize')]
    public function validPolicyTreeFail(ValidatorState $state)
    {
        $this->expectException(LogicException::class);
        $state->withoutValidPolicyTree()
            ->validPolicyTree();
    }

    #[Test]
    #[Depends('initialize')]
    public function workingPublicKeyParameters(ValidatorState $state)
    {
        static::assertInstanceOf(NullType::class, $state->workingPublicKeyParameters());
    }
}
