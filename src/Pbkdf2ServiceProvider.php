<?php

namespace OliLaban\LaravelPbkdf2Hasher;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\ServiceProvider;

/** @phpstan-import-type Options from Pbkdf2Hasher */
class Pbkdf2ServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Hash::extend('pbkdf2', function (Application $app) {
            /** @var Options $options */
            $options = $app->make(Repository::class)->get('pbkdf2') ?? [];

            return new Pbkdf2Hasher($options);
        });
    }
}
