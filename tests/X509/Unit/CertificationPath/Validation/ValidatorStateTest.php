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
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\ValidatorState;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;

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

    #[Test]
    #[Depends('initialize')]
    public function noNameConstraintsByDefault(ValidatorState $state)
    {
        static::assertSame([], $state->permittedSubtrees());
        static::assertNull($state->excludedSubtrees());
    }

    #[Test]
    #[Depends('initialize')]
    public function permittedSubtreesAreAccumulated(ValidatorState $state)
    {
        $first = GeneralSubtrees::create(GeneralSubtree::create(DNSName::create('example.com')));
        $second = GeneralSubtrees::create(GeneralSubtree::create(DNSName::create('example.org')));
        $new = $state->withAdditionalPermittedSubtrees($first)
            ->withAdditionalPermittedSubtrees($second);
        static::assertSame([$first, $second], $new->permittedSubtrees());
        // the original state is left untouched
        static::assertSame([], $state->permittedSubtrees());
    }

    #[Test]
    #[Depends('initialize')]
    public function excludedSubtreesAreUnited(ValidatorState $state)
    {
        $first = GeneralSubtree::create(DNSName::create('example.com'));
        $second = GeneralSubtree::create(DNSName::create('example.org'));
        $new = $state->withAdditionalExcludedSubtrees(GeneralSubtrees::create($first))
            ->withAdditionalExcludedSubtrees(GeneralSubtrees::create($second));
        static::assertSame([$first, $second], $new->excludedSubtrees()->all());
        // the original state is left untouched
        static::assertNull($state->excludedSubtrees());
    }
}
