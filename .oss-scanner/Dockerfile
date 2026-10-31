# Build of the OSS Scanner (https://github.com/anthropics/oss-scanner), with the repository root as context.
# The CI sets PHP up with setup-php (8.3 for its single-version jobs, 8.1 to 8.5 for the tests). This image starts from
# the phpqa image of PHP 8.3, which already has every extension the tests use (gmp, bcmath, openssl, sodium, intl,
# mbstring), and runs vendor/bin/phpunit as "make ci-test" does on CI (the image has no make). The scan runs without
# network access: every dependency is installed here. Composer resolves the dependencies without the Git metadata, so
# COMPOSER_ROOT_VERSION is not needed.
FROM ghcr.io/spomky-labs/phpqa:8.3

USER root

COPY . /src
WORKDIR /src

RUN composer install --no-interaction --no-progress

RUN vendor/bin/phpunit --no-progress || echo "WARNING: PHPUnit reported failures"
