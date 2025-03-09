<?php

namespace OliLaban\LaravelPbkdf2Hasher;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Hashing\AbstractHasher;
use SensitiveParameter;

/**
 * @phpstan-type Options array{
 *      'algo'?: non-falsy-string,
 *      'iterations'?: int<1, max>,
 *      'hash_length'?: int<1, max>,
 *      'salt_length'?: int<1, max>,
 *  }
 */
class Pbkdf2Hasher extends AbstractHasher implements Hasher
{
    /** @var non-falsy-string */
    protected string $algo = 'sha256';

    /** @var int<1, max> */
    protected int $iterations = 210000;

    /** @var int<1, max> */
    protected int $hashLength = 32;

    /** @var int<1, max> */
    protected int $saltLength = 16;

    /** @var callable(int): string */
    protected $saltGenerator;

    /** @param Options $options */
    public function __construct(array $options = [], ?callable $saltGenerator = null)
    {
        $this->algo = $options['algo'] ?? $this->algo;
        $this->iterations = $options['iterations'] ?? $this->iterations;
        $this->hashLength = $options['hash_length'] ?? $this->hashLength;
        $this->saltLength = $options['salt_length'] ?? $this->saltLength;
        $this->saltGenerator = $saltGenerator ?? fn ($length) => random_bytes($length);
    }

    /** @param Options $options */
    public function make(
        #[SensitiveParameter] $value,
        array $options = [],
    ): string {
        $algo = $options['algo'] ?? $this->algo;
        $iterations = $options['iterations'] ?? $this->iterations;
        $hashLength = $options['hash_length'] ?? $this->hashLength;
        $saltLength = $options['salt_length'] ?? $this->saltLength;

        $salt = $this->generateSalt($saltLength);

        $hash = hash_pbkdf2($algo, $value, $salt, $iterations, $hashLength, binary: true);

        $encodedSalt = base64_encode($salt);
        $encodedHash = base64_encode($hash);

        return "pbkdf2-$algo$".$iterations.'$'.$encodedSalt.'$'.$encodedHash;
    }

    /** @param Options $options */
    public function check(
        #[SensitiveParameter] $value,
        $hashedValue,
        array $options = [],
    ): bool {
        if ($hashedValue === '') {
            return false;
        }

        $info = $this->info($hashedValue);

        if (! $info) {
            return false;
        }

        $hash = hash_pbkdf2(
            $info['algo'],
            $value,
            $info['salt'],
            $info['iterations'],
            $info['hash_length'],
            binary: true,
        );

        return hash_equals($info['hash'], $hash);
    }


    /** @param Options $options */
    public function needsRehash($hashedValue, array $options = []): bool
    {
        $algo = $options['algo'] ?? $this->algo;
        $iterations = $options['iterations'] ?? $this->iterations;
        $hashLength = $options['hash_length'] ?? $this->hashLength;
        $saltLength = $options['salt_length'] ?? $this->saltLength;

        $info = $this->info($hashedValue);

        return ! $info
            || $info['algo'] !== $algo
            || $info['iterations'] !== $iterations
            || $info['hash_length'] !== $hashLength
            || $info['salt_length'] !== $saltLength;
    }

    /**
     * @return array{
     *     'algo': non-falsy-string,
     *     'iterations': int<1, max>,
     *     'salt': non-falsy-string,
     *     'salt_length': int<1, max>,
     *     'hash': non-falsy-string,
     *     'hash_length': int<1, max>,
     * }|null
     */
    public function info($hashedValue): ?array
    {
        $parts = explode('$', $hashedValue);

        if (count($parts) !== 4) {
            return null;
        }

        $algo = str_replace('pbkdf2-', '', $parts[0]);
        $iterations = ctype_digit($parts[1]) ? (int) $parts[1] : null;
        $salt = base64_decode($parts[2], strict: true);
        $hash = base64_decode($parts[3], strict: true);

        if (! $this->validateParts($algo, $iterations, $salt, $hash)) {
            return null;
        }

        return [
            'algo' => $algo,
            'iterations' => $iterations,
            'salt' => $salt,
            'salt_length' => strlen($salt),
            'hash' => $hash,
            'hash_length' => strlen($hash),
        ];
    }

    /**
     * @phpstan-assert-if-true non-falsy-string $algo
     * @phpstan-assert-if-true int<1, max> $iterations
     * @phpstan-assert-if-true non-falsy-string $salt
     * @phpstan-assert-if-true non-falsy-string $hash
     */
    protected function validateParts(
        string $algo,
        ?int $iterations,
        string|false $salt,
        string|false $hash,
    ): bool {
        return $algo !== ''
            && $iterations > 0
            && $salt !== false
            && $salt !== ''
            && $hash !== false
            && $hash !== '';
    }

    protected function generateSalt(int $length): string
    {
        return call_user_func($this->saltGenerator, $length);
    }
}
