<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
use Rector\PHPUnit\CodeQuality\Rector\ClassMethod\DataProviderArrayItemsNewLinedRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Set\SymfonySetList;
use Rector\ValueObject\PhpVersion;

return static function (RectorConfig $config): void {
    $config->import(SetList::DEAD_CODE);
    $config->import(SetList::PHP_81);
    $config->import(SymfonySetList::SYMFONY_50_TYPES);
    $config->import(SymfonySetList::SYMFONY_CODE_QUALITY);
    $config->import(SymfonySetList::SYMFONY_CONSTRUCTOR_INJECTION);
    $config->import(PHPUnitSetList::PHPUNIT_CODE_QUALITY);
    $config->import(PHPUnitSetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->paths([__DIR__ . '/src', __DIR__ . '/tests', __DIR__ . '/ecs.php', __DIR__ . '/rector.php']);
    $config->skip([DataProviderArrayItemsNewLinedRector::class, PreferPHPUnitThisCallRector::class]);
    $config::configure()->withComposerBased(twig: true, phpunit: true);
    $config::configure()->withPhpSets();
    $config::configure()->withAttributesSets();
    $config->phpVersion(PhpVersion::PHP_81);
    $config->parallel();
    $config->importNames();
    $config->importShortClasses();
};
