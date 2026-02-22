# LiteSOC PHP SDK

Official PHP SDK for [LiteSOC](https://www.litesoc.io) - Security event tracking and threat detection for your applications.

[![Latest Stable Version](https://poser.pugx.org/litesoc/litesoc-php/v)](https://packagist.org/packages/litesoc/litesoc-php)
[![PHP Version](https://img.shields.io/packagist/php-v/litesoc/litesoc-php)](https://packagist.org/packages/litesoc/litesoc-php)
[![License](https://poser.pugx.org/litesoc/litesoc-php/license)](https://packagist.org/packages/litesoc/litesoc-php)

## Installation

```bash
composer require litesoc/litesoc-php
```

## Quick Start

```php
use LiteSOC\LiteSOC;

// Initialize the SDK
$litesoc = new LiteSOC('your-api-key');

// Track a login failure
$litesoc->track('auth.login_failed', [
    'actor_id' => 'user_123',
    'actor_email' => 'user@example.com',
    'user_ip' => '192.168.1.1',
    'metadata' => ['reason' => 'invalid_password']
]);

// Flush remaining events before shutdown
$litesoc->flush();
```

## Features

- ✅ **50+ pre-defined security event types** - Authentication, authorization, data access, and more
- ✅ **Automatic batching** - Events are batched for efficient delivery
- ✅ **Retry logic** - Failed events are automatically retried
- ✅ **Laravel integration** - Service provider, facade, and config publishing
- ✅ **PHP 8.0+** - Modern PHP with full type declarations

## Configuration Options

```php
use LiteSOC\LiteSOC;

$litesoc = new LiteSOC('your-api-key', [
    'endpoint' => 'https://...',      // Custom API endpoint
    'batching' => true,                // Enable event batching (default: true)
    'batch_size' => 10,                // Events before auto-flush (default: 10)
    'flush_interval' => 5.0,           // Seconds between auto-flushes (default: 5.0)
    'debug' => false,                  // Enable debug logging (default: false)
    'silent' => true,                  // Fail silently on errors (default: true)
    'timeout' => 30.0,                 // Request timeout in seconds (default: 30.0)
]);
```

## Tracking Events

### Basic Usage

```php
// Track any event type
$litesoc->track('auth.login_failed', [
    'actor_id' => 'user_123',
    'actor_email' => 'user@example.com',
    'user_ip' => '192.168.1.1'
]);
```

### Using Event Type Constants

```php
use LiteSOC\EventType;

$litesoc->track(EventType::AUTH_LOGIN_FAILED, [
    'actor_id' => 'user_123',
    'user_ip' => '192.168.1.1'
]);
```

### With Severity Level

```php
use LiteSOC\EventSeverity;

$litesoc->track('security.suspicious_activity', [
    'actor_id' => 'user_123',
    'user_ip' => '192.168.1.1',
    'severity' => EventSeverity::CRITICAL,
    'metadata' => ['reason' => 'impossible travel detected']
]);
```

### With Metadata

```php
$litesoc->track('data.export', [
    'actor_id' => 'user_123',
    'user_ip' => '192.168.1.1',
    'metadata' => [
        'file_type' => 'csv',
        'record_count' => 1000,
        'export_reason' => 'monthly_report'
    ]
]);
```

## Convenience Methods

The SDK provides convenience methods for common security events:

```php
// Track login failures
$litesoc->trackLoginFailed('user_123', ['user_ip' => '192.168.1.1']);

// Track login successes
$litesoc->trackLoginSuccess('user_123', ['user_ip' => '192.168.1.1']);

// Track privilege escalation (critical severity)
$litesoc->trackPrivilegeEscalation('admin_user', ['user_ip' => '192.168.1.1']);

// Track sensitive data access (high severity)
$litesoc->trackSensitiveAccess('user_123', 'customer_pii_table', ['user_ip' => '192.168.1.1']);

// Track bulk deletions (high severity)
$litesoc->trackBulkDelete('admin_user', 500, ['user_ip' => '192.168.1.1']);

// Track role changes
$litesoc->trackRoleChanged('user_123', 'viewer', 'admin', ['user_ip' => '192.168.1.1']);

// Track access denied
$litesoc->trackAccessDenied('user_123', '/admin/settings', ['user_ip' => '192.168.1.1']);
```

## Laravel Integration

### Installation

```bash
composer require litesoc/litesoc-php
```

The package auto-discovers the service provider and facade.

### Configuration

Publish the config file:

```bash
php artisan vendor:publish --tag=litesoc-config
```

Add your API key to `.env`:

```env
LITESOC_API_KEY=your-api-key
```

### Usage with Facade

```php
use LiteSOC\Laravel\Facades\LiteSOC;

// Track events using the facade
LiteSOC::track('auth.login_failed', [
    'actor_id' => auth()->id(),
    'user_ip' => request()->ip()
]);

// Use convenience methods
LiteSOC::trackLoginSuccess(auth()->id(), [
    'actor_email' => auth()->user()->email,
    'user_ip' => request()->ip()
]);
```

### Usage with Dependency Injection

```php
use LiteSOC\LiteSOC;

class LoginController extends Controller
{
    public function __construct(
        private LiteSOC $litesoc
    ) {}

    public function login(Request $request)
    {
        // Attempt authentication
        if (Auth::attempt($request->only('email', 'password'))) {
            $this->litesoc->trackLoginSuccess(auth()->id(), [
                'actor_email' => auth()->user()->email,
                'user_ip' => $request->ip()
            ]);
            return redirect('/dashboard');
        }

        $this->litesoc->trackLoginFailed($request->email, [
            'user_ip' => $request->ip()
        ]);
        return back()->withErrors(['email' => 'Invalid credentials']);
    }
}
```

### Event Listener Integration

```php
// app/Providers/EventServiceProvider.php
protected $listen = [
    \Illuminate\Auth\Events\Login::class => [
        \App\Listeners\TrackLoginSuccess::class,
    ],
    \Illuminate\Auth\Events\Failed::class => [
        \App\Listeners\TrackLoginFailed::class,
    ],
];

// app/Listeners/TrackLoginSuccess.php
use LiteSOC\Laravel\Facades\LiteSOC;
use Illuminate\Auth\Events\Login;

class TrackLoginSuccess
{
    public function handle(Login $event): void
    {
        LiteSOC::trackLoginSuccess($event->user->id, [
            'actor_email' => $event->user->email,
            'user_ip' => request()->ip()
        ]);
    }
}

// app/Listeners/TrackLoginFailed.php
use LiteSOC\Laravel\Facades\LiteSOC;
use Illuminate\Auth\Events\Failed;

class TrackLoginFailed
{
    public function handle(Failed $event): void
    {
        LiteSOC::trackLoginFailed($event->credentials['email'] ?? 'unknown', [
            'user_ip' => request()->ip()
        ]);
    }
}
```

### Middleware for Auth Events

```php
// app/Http/Middleware/TrackSecurityEvents.php
namespace App\Http\Middleware;

use Closure;
use LiteSOC\Laravel\Facades\LiteSOC;

class TrackSecurityEvents
{
    public function handle($request, Closure $next)
    {
        return $next($request);
    }

    public function terminate($request, $response)
    {
        // Track access denied (403 responses)
        if ($response->status() === 403) {
            LiteSOC::trackAccessDenied(
                auth()->id() ?? 'anonymous',
                $request->path(),
                ['user_ip' => $request->ip()]
            );
        }
    }
}
```

## Event Types

### Authentication Events
- `auth.login_success`
- `auth.login_failed`
- `auth.logout`
- `auth.password_changed`
- `auth.password_reset_requested`
- `auth.password_reset_completed`
- `auth.mfa_enabled`
- `auth.mfa_disabled`
- `auth.mfa_challenge_success`
- `auth.mfa_challenge_failed`
- `auth.session_created`
- `auth.session_revoked`
- `auth.token_refreshed`

### User Events
- `user.created`
- `user.updated`
- `user.deleted`
- `user.email_changed`
- `user.email_verified`
- `user.profile_updated`

### Authorization Events
- `authz.role_assigned`
- `authz.role_removed`
- `authz.role_changed`
- `authz.permission_granted`
- `authz.permission_revoked`
- `authz.access_denied`
- `authz.access_granted`

### Admin Events
- `admin.privilege_escalation`
- `admin.user_impersonation`
- `admin.settings_changed`
- `admin.api_key_created`
- `admin.api_key_revoked`
- `admin.invite_sent`
- `admin.invite_accepted`
- `admin.member_removed`

### Data Events
- `data.export`
- `data.import`
- `data.bulk_delete`
- `data.bulk_update`
- `data.sensitive_access`
- `data.download`
- `data.upload`
- `data.shared`
- `data.unshared`

### Security Events
- `security.suspicious_activity`
- `security.rate_limit_exceeded`
- `security.ip_blocked`
- `security.ip_unblocked`
- `security.account_locked`
- `security.account_unlocked`
- `security.brute_force_detected`
- `security.impossible_travel`
- `security.geo_anomaly`

### API Events
- `api.key_used`
- `api.rate_limited`
- `api.error`
- `api.webhook_sent`
- `api.webhook_failed`

### Billing Events
- `billing.subscription_created`
- `billing.subscription_updated`
- `billing.subscription_cancelled`
- `billing.payment_succeeded`
- `billing.payment_failed`

## Queue Management

```php
// Get current queue size
$queueSize = $litesoc->getQueueSize();

// Manually flush all events
$litesoc->flush();

// Clear queue without sending
$litesoc->clearQueue();

// Graceful shutdown
$litesoc->shutdown();
```

## Error Handling

By default, the SDK fails silently (`silent => true`). To catch errors:

```php
$litesoc = new LiteSOC('your-api-key', ['silent' => false]);

try {
    $litesoc->track('auth.login_failed', ['actor_id' => 'user_123']);
    $litesoc->flush();
} catch (\Exception $e) {
    // Handle error
    error_log("Failed to track event: " . $e->getMessage());
}
```

## Debug Mode

Enable debug logging to troubleshoot issues:

```php
$litesoc = new LiteSOC('your-api-key', ['debug' => true]);
// Logs will be printed to stdout
```

For Laravel, set in your `.env`:

```env
LITESOC_DEBUG=true
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [LiteSOC Website](https://www.litesoc.io)
- [Documentation](https://www.litesoc.io/docs)
- [API Reference](https://www.litesoc.io/docs/api)
- [GitHub Repository](https://github.com/litesoc/litesoc-php)
