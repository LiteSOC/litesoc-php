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

// Track a login failure - LiteSOC auto-enriches with GeoIP & Network Intelligence
$litesoc->track('auth.login_failed', [
    'actor_id' => 'user_123',
    'actor_email' => 'user@example.com',
    'user_ip' => '192.168.1.1',  // Required for Security Intelligence
    'metadata' => ['reason' => 'invalid_password']
]);

// Flush remaining events before shutdown
$litesoc->flush();
```

## Features

- ✅ **26 standard security event types** - Authentication, authorization, admin, data, and security events
- ✅ **Automatic batching** - Events are batched for efficient delivery
- ✅ **Retry logic** - Failed events are automatically retried
- ✅ **Laravel integration** - Service provider, facade, and config publishing
- ✅ **PHP 8.0+** - Modern PHP with full type declarations
- 🗺️ **GeoIP Enrichment** - Automatic location data from IP addresses
- 🛡️ **Network Intelligence** - VPN, Tor, Proxy & Datacenter detection
- 📊 **Threat Scoring** - Auto-assigned severity (Low → Critical)

## Security Intelligence (Automatic Enrichment)

When you provide `user_ip`, LiteSOC automatically enriches your events with:

### 🗺️ Geolocation
- Country & City resolution
- Latitude/Longitude coordinates
- Interactive map visualization in dashboard

### 🛡️ Network Intelligence
- **VPN Detection** - NordVPN, ExpressVPN, Surfshark, etc.
- **Tor Exit Nodes** - Anonymizing network detection
- **Proxy Detection** - HTTP/SOCKS proxy identification
- **Datacenter IPs** - AWS, GCP, Azure, DigitalOcean, etc.

### 📊 Threat Scoring
Events are auto-classified by severity:
- **Low** - Normal activity
- **Medium** - Unusual patterns
- **High** - Suspicious behavior
- **Critical** - Active threats (triggers instant alerts)

> **Important**: Always include `user_ip` for full Security Intelligence features.

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

### 26 Standard Events (Primary)

These are the primary events for comprehensive security coverage:

| Category | Event Type | Description |
|----------|------------|-------------|
| **Auth** | `auth.login_success` | Successful user login |
| **Auth** | `auth.login_failed` | Failed login attempt |
| **Auth** | `auth.logout` | User logout |
| **Auth** | `auth.password_reset` | Password reset completed |
| **Auth** | `auth.mfa_enabled` | MFA enabled on account |
| **Auth** | `auth.mfa_disabled` | MFA disabled on account |
| **Auth** | `auth.session_expired` | Session timeout/expiry |
| **Auth** | `auth.token_refreshed` | Token refresh |
| **Authz** | `authz.role_changed` | User role modified |
| **Authz** | `authz.permission_granted` | Permission assigned |
| **Authz** | `authz.permission_revoked` | Permission removed |
| **Authz** | `authz.access_denied` | Access denied event |
| **Admin** | `admin.privilege_escalation` | Admin privilege escalation |
| **Admin** | `admin.user_impersonation` | Admin impersonating user |
| **Admin** | `admin.settings_changed` | System settings modified |
| **Admin** | `admin.api_key_created` | New API key generated |
| **Admin** | `admin.api_key_revoked` | API key revoked |
| **Admin** | `admin.user_suspended` | User account suspended |
| **Admin** | `admin.user_deleted` | User account deleted |
| **Data** | `data.bulk_delete` | Bulk data deletion |
| **Data** | `data.sensitive_access` | PII/sensitive data accessed |
| **Data** | `data.export` | Data export operation |
| **Security** | `security.suspicious_activity` | Suspicious behavior detected |
| **Security** | `security.rate_limit_exceeded` | Rate limit triggered |
| **Security** | `security.ip_blocked` | IP address blocked |
| **Security** | `security.brute_force_detected` | Brute force attack detected |

### Extended Events (Backward Compatible)

Additional events for granular tracking:

- `auth.password_changed`, `auth.password_reset_requested`, `auth.mfa_challenge_success`, `auth.mfa_challenge_failed`, `auth.session_created`
- `user.created`, `user.updated`, `user.deleted`, `user.email_changed`, `user.profile_updated`
- `authz.role_assigned`, `authz.role_removed`, `authz.access_granted`
- `admin.invite_sent`, `admin.invite_accepted`, `admin.member_removed`
- `data.import`, `data.bulk_update`, `data.download`, `data.upload`, `data.shared`
- `security.ip_unblocked`, `security.account_locked`, `security.impossible_travel`, `security.geo_anomaly`
- `api.key_used`, `api.rate_limited`, `api.error`, `api.webhook_sent`, `api.webhook_failed`
- `billing.subscription_created`, `billing.subscription_cancelled`, `billing.payment_succeeded`, `billing.payment_failed`

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
