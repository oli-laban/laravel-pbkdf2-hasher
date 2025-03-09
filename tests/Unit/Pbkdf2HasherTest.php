<?php

use OliLaban\LaravelPbkdf2Hasher\Pbkdf2Hasher;

beforeEach(function () {
    $this->hasher = new Pbkdf2Hasher;

    $this->deterministicHasher = new Pbkdf2Hasher(
        saltGenerator: fn (int $length) => str_repeat('A', $length)
    );
});

it('can hash a string value', function () {
    $hash = $this->hasher->make('password');

    expect($hash)
        ->toBeString()
        ->and($hash)
        ->toContain('pbkdf2-sha256$')
        ->and(explode('$', $hash))
        ->toHaveCount(4);
});

it('can verify a correct password', function () {
    $hash = $this->hasher->make('password');

    expect($this->hasher->check('password', $hash))
        ->toBeTrue();
});

it('rejects an incorrect password', function () {
    $hash = $this->hasher->make('password');

    expect($this->hasher->check('wrong-password', $hash))
        ->toBeFalse();
});

it('uses default options when instantiating the hasher', function () {
    $hash = $this->hasher->make('password');
    $info = $this->hasher->info($hash);

    expect($info['algo'])
        ->toBe('sha256')
        ->and($info['iterations'])
        ->toBe(210000)
        ->and($info['salt_length'])
        ->toBe(16)
        ->and($info['hash_length'])
        ->toBe(32);
});

it('supports custom options when creating a hash', function () {
    $hash = $this->hasher->make('password', [
        'algo' => 'sha512',
        'iterations' => 100000,
        'salt_length' => 32,
        'hash_length' => 64,
    ]);
    $info = $this->hasher->info($hash);

    expect($info['algo'])
        ->toBe('sha512')
        ->and($info['iterations'])
        ->toBe(100000)
        ->and($info['salt_length'])
        ->toBe(32)
        ->and($info['hash_length'])
        ->toBe(64);
});

it('can be instantiated with custom options', function () {
    $hasher = new Pbkdf2Hasher([
        'algo' => 'sha512',
        'iterations' => 100000,
        'salt_length' => 32,
        'hash_length' => 64,
    ]);

    $hash = $hasher->make('password');
    $info = $hasher->info($hash);

    expect($info['algo'])
        ->toBe('sha512')
        ->and($info['iterations'])
        ->toBe(100000)
        ->and($info['salt_length'])
        ->toBe(32)
        ->and($info['hash_length'])
        ->toBe(64);
});

it('produces deterministic hashes with the same parameters', function () {
    $hash1 = $this->deterministicHasher->make('password');
    $hash2 = $this->deterministicHasher->make('password');

    expect($hash1)
        ->toBe($hash2);
});

it('identifies the password needs rehashing when the algo changes', function () {
    $hash = $this->hasher->make('password');

    expect($this->hasher->needsRehash($hash, ['algo' => 'sha512']))
        ->toBeTrue();
});

it('identifies the password needs rehashing when the number of iterations changes', function () {
    $hash = $this->hasher->make('password');

    expect($this->hasher->needsRehash($hash, ['iterations' => 100000]))
        ->toBeTrue();
});

it('identifies the password needs rehashing when the salt length changes', function () {
    $hash = $this->hasher->make('password');

    expect($this->hasher->needsRehash($hash, ['salt_length' => 32]))
        ->toBeTrue();
});

it('identifies the password needs rehashing when the hash length changes', function () {
    $hash = $this->hasher->make('password');

    expect($this->hasher->needsRehash($hash, ['hash_length' => 64]))
        ->toBeTrue();
});

it('identifies the password does not need rehashing with identical options', function () {
    $hash = $this->hasher->make('password', [
        'algo' => 'sha512',
        'iterations' => 210000,
        'salt_length' => 16,
        'hash_length' => 32,
    ]);
    $result = $this->hasher->needsRehash($hash, [
        'algo' => 'sha512',
        'iterations' => 210000,
        'salt_length' => 16,
        'hash_length' => 32,
    ]);

    expect($result)
        ->toBeFalse();
});

it('returns the correct info for a valid hash', function () {
    $salt = random_bytes(16);
    $hash = hash_pbkdf2('sha256', 'password', $salt, 210000, 32, true);

    $encodedSalt = base64_encode($salt);
    $encodedHash = base64_encode($hash);

    $hashString = 'pbkdf2-sha256$210000$'.$encodedSalt.'$'.$encodedHash;

    $info = $this->hasher->info($hashString);

    expect($info)
        ->toHaveKeys(['algo', 'iterations', 'salt', 'salt_length', 'hash',  'hash_length'])
        ->and($info['algo'])
        ->toBe('sha256')
        ->and($info['iterations'])
        ->toBe(210000)
        ->and($info['salt'])
        ->toBe($salt)
        ->and($info['salt_length'])
        ->toBe(16)
        ->and($info['hash'])
        ->toBe($hash)
        ->and($info['hash_length'])
        ->toBe(32);
});

it('returns null info for invalid hash format', function () {
    expect($this->hasher->info('invalid-hash'))
        ->toBeNull()
        ->and($this->hasher->info('pbkdf2-sha256$iterations$salt'))
        ->toBeNull()
        ->and($this->hasher->info(
            'pbkdf2-sha256$not-a-number$'.base64_encode('salt').'$'.base64_encode('hash'),
        ))
        ->toBeNull();
});

it('returns null info for hash with invalid base64 encoding', function () {
    expect($this->hasher->info('pbkdf2-sha256$210000$invalid-base%64$'.base64_encode('hash')))
        ->toBeNull()
        ->and($this->hasher->info('pbkdf2-sha256$210000$'.base64_encode('salt').'$invalid-base%64'))
        ->toBeNull();
});

it('handles different algos', function () {
    $hasher = new Pbkdf2Hasher(['algo' => 'sha512']);
    $hash = $hasher->make('password');

    expect($hasher->check('password', $hash))
        ->toBeTrue()
        ->and($hasher->info($hash)['algo'])
        ->toBe('sha512');
});

it('handles different salt and hash lengths', function () {
    $hasher = new Pbkdf2Hasher(['salt_length' => 32, 'hash_length' => 64]);
    $hash = $hasher->make('password');
    $info = $hasher->info($hash);

    expect($hasher->check('password', $hash))
        ->toBeTrue()
        ->and($info['salt_length'])
        ->toBe(32)
        ->and($info['hash_length'])
        ->toBe(64);
});

it('handles different iteration numbers', function () {
    $lowIterations = new Pbkdf2Hasher(['iterations' => 1000]);
    $highIterations = new Pbkdf2Hasher(['iterations' => 210000]);

    $hash1 = $lowIterations->make('password');
    $hash2 = $highIterations->make('password');

    expect($lowIterations->check('password', $hash1))
        ->toBeTrue()
        ->and($lowIterations->check('password', $hash2))
        ->toBeTrue()
        ->and($highIterations->check('password', $hash1))
        ->toBeTrue()
        ->and($highIterations->check('password', $hash2))
        ->toBeTrue()
        ->and($lowIterations->needsRehash($hash2))
        ->toBeTrue()
        ->and($highIterations->needsRehash($hash1))
        ->toBeTrue();
});

it('uses the provided salt generator', function () {
    $generatedSalt = 'XXXXXXXXXXXX';
    $saltGenerator = fn ($length) => str_repeat('X', 12);

    $hasher = new Pbkdf2Hasher(saltGenerator: $saltGenerator);
    $hash = $hasher->make('password', ['salt_length' => 12]);
    $info = $hasher->info($hash);

    expect($info['salt'])
        ->toBe($generatedSalt)
        ->and($info['salt_length'])
        ->toBe(12);
});
