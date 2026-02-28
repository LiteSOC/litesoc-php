<?php

declare(strict_types=1);

namespace LiteSOC\Laravel;

use Illuminate\Support\ServiceProvider;
use LiteSOC\LiteSOC;

class LiteSOCServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/litesoc.php',
            'litesoc'
        );

        $this->app->singleton(LiteSOC::class, function ($app) {
            $config = $app['config']['litesoc'];

            return new LiteSOC($config['api_key'], [
                'base_url' => $config['base_url'] ?? LiteSOC::DEFAULT_BASE_URL,
                'endpoint' => $config['endpoint'] ?? null, // Legacy support
                'batching' => $config['batching'] ?? true,
                'batch_size' => $config['batch_size'] ?? 10,
                'flush_interval' => $config['flush_interval'] ?? 5.0,
                'debug' => $config['debug'] ?? false,
                'silent' => $config['silent'] ?? true,
                'timeout' => $config['timeout'] ?? 30.0,
            ]);
        });

        $this->app->alias(LiteSOC::class, 'litesoc');
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/litesoc.php' => config_path('litesoc.php'),
            ], 'litesoc-config');
        }

        // Register shutdown handler to flush events
        $this->app->terminating(function () {
            $this->app->make(LiteSOC::class)->flush();
        });
    }
}
