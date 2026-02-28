<?php

return [
    /*
    |--------------------------------------------------------------------------
    | LiteSOC API Key
    |--------------------------------------------------------------------------
    |
    | Your LiteSOC API key. You can find this in your LiteSOC dashboard
    | under Settings > API Keys.
    |
    */

    'api_key' => env('LITESOC_API_KEY', ''),

    /*
    |--------------------------------------------------------------------------
    | Base URL
    |--------------------------------------------------------------------------
    |
    | The LiteSOC API base URL. You typically don't need to change this
    | unless you're using a custom deployment.
    |
    */

    'base_url' => env('LITESOC_BASE_URL', 'https://api.litesoc.io'),

    /*
    |--------------------------------------------------------------------------
    | API Endpoint (Legacy)
    |--------------------------------------------------------------------------
    |
    | Legacy option for backward compatibility. Use 'base_url' instead.
    | If set, this overrides the collect endpoint specifically.
    |
    */

    'endpoint' => env('LITESOC_ENDPOINT'),

    /*
    |--------------------------------------------------------------------------
    | Batching
    |--------------------------------------------------------------------------
    |
    | Enable event batching for more efficient delivery. When enabled,
    | events are queued and sent in batches.
    |
    */

    'batching' => env('LITESOC_BATCHING', true),

    /*
    |--------------------------------------------------------------------------
    | Batch Size
    |--------------------------------------------------------------------------
    |
    | The number of events to queue before automatically flushing.
    |
    */

    'batch_size' => env('LITESOC_BATCH_SIZE', 10),

    /*
    |--------------------------------------------------------------------------
    | Flush Interval
    |--------------------------------------------------------------------------
    |
    | The interval (in seconds) between automatic flushes.
    |
    */

    'flush_interval' => env('LITESOC_FLUSH_INTERVAL', 5.0),

    /*
    |--------------------------------------------------------------------------
    | Debug Mode
    |--------------------------------------------------------------------------
    |
    | Enable debug logging. This will output debug messages to stdout.
    |
    */

    'debug' => env('LITESOC_DEBUG', false),

    /*
    |--------------------------------------------------------------------------
    | Silent Mode
    |--------------------------------------------------------------------------
    |
    | When enabled, errors are silently logged instead of thrown.
    | Recommended for production environments.
    |
    */

    'silent' => env('LITESOC_SILENT', true),

    /*
    |--------------------------------------------------------------------------
    | Request Timeout
    |--------------------------------------------------------------------------
    |
    | The timeout (in seconds) for API requests.
    |
    */

    'timeout' => env('LITESOC_TIMEOUT', 30.0),
];
