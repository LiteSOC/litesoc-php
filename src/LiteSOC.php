<?php

declare(strict_types=1);

namespace LiteSOC;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use LiteSOC\Exceptions\LiteSOCException;
use LiteSOC\Exceptions\AuthenticationException;
use LiteSOC\Exceptions\RateLimitException;
use LiteSOC\Exceptions\PlanRestrictedException;

/**
 * LiteSOC SDK for tracking security events
 *
 * @example
 * ```php
 * use LiteSOC\LiteSOC;
 *
 * $litesoc = new LiteSOC('your-api-key');
 *
 * // Track a login failure
 * $litesoc->track('auth.login_failed', [
 *     'actor_id' => 'user_123',
 *     'actor_email' => 'user@example.com',
 *     'user_ip' => '192.168.1.1',
 *     'metadata' => ['reason' => 'invalid_password']
 * ]);
 *
 * // Flush remaining events
 * $litesoc->flush();
 *
 * // Management API (Business/Enterprise plans)
 * $alerts = $litesoc->getAlerts(['severity' => 'critical']);
 * $events = $litesoc->getEvents(20);
 * ```
 */
class LiteSOC
{
    public const VERSION = '2.0.0';
    public const DEFAULT_BASE_URL = 'https://api.litesoc.io';

    private string $apiKey;
    private string $baseUrl;
    private string $endpoint;
    private bool $batching;
    private int $batchSize;
    private float $flushInterval;
    private bool $debug;
    private bool $silent;
    private float $timeout;

    /** @var array<int, array<string, mixed>> */
    private array $queue = [];

    private ?Client $client = null;

    /**
     * Initialize the LiteSOC SDK
     *
     * @param string $apiKey Your LiteSOC API key (required)
     * @param array{
     *     base_url?: string,
     *     endpoint?: string,
     *     batching?: bool,
     *     batch_size?: int,
     *     flush_interval?: float,
     *     debug?: bool,
     *     silent?: bool,
     *     timeout?: float,
     * } $options Configuration options
     *
     * @throws \InvalidArgumentException If API key is not provided
     */
    public function __construct(string $apiKey, array $options = [])
    {
        if (empty($apiKey)) {
            throw new \InvalidArgumentException('LiteSOC: api_key is required');
        }

        $this->apiKey = $apiKey;
        $this->baseUrl = $options['base_url'] ?? self::DEFAULT_BASE_URL;
        // Support legacy 'endpoint' option for backward compatibility
        $this->endpoint = $options['endpoint'] ?? $this->baseUrl . '/collect';
        $this->batching = $options['batching'] ?? true;
        $this->batchSize = $options['batch_size'] ?? 10;
        $this->flushInterval = $options['flush_interval'] ?? 5.0;
        $this->debug = $options['debug'] ?? false;
        $this->silent = $options['silent'] ?? true;
        $this->timeout = $options['timeout'] ?? 30.0;

        $this->log('Initialized with base_url: ' . $this->baseUrl);
    }

    /**
     * Track a security event
     *
     * @param string $eventName The event type (e.g., 'auth.login_failed')
     * @param array{
     *     actor_id?: string,
     *     actor_email?: string,
     *     actor?: array{id: string, email?: string}|string,
     *     user_ip?: string,
     *     severity?: string,
     *     metadata?: array<string, mixed>,
     *     timestamp?: string|\DateTimeInterface,
     * } $options Event options
     */
    public function track(string $eventName, array $options = []): void
    {
        try {
            // Normalize actor
            $actor = null;

            if (isset($options['actor'])) {
                if (is_string($options['actor'])) {
                    $actor = [
                        'id' => $options['actor'],
                        'email' => $options['actor_email'] ?? null,
                    ];
                } elseif (is_array($options['actor'])) {
                    $actor = [
                        'id' => $options['actor']['id'],
                        'email' => $options['actor']['email'] ?? $options['actor_email'] ?? null,
                    ];
                }
            } elseif (isset($options['actor_id'])) {
                $actor = [
                    'id' => $options['actor_id'],
                    'email' => $options['actor_email'] ?? null,
                ];
            } elseif (isset($options['actor_email'])) {
                $actor = [
                    'id' => $options['actor_email'],
                    'email' => $options['actor_email'],
                ];
            }

            // Normalize timestamp
            $timestamp = $options['timestamp'] ?? null;
            if ($timestamp === null) {
                $timestamp = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format(\DateTimeInterface::ATOM);
            } elseif ($timestamp instanceof \DateTimeInterface) {
                $timestamp = $timestamp->format(\DateTimeInterface::ATOM);
            }

            // Build metadata
            $metadata = $options['metadata'] ?? [];
            $metadata['_sdk'] = 'litesoc-php';
            $metadata['_sdk_version'] = self::VERSION;

            if (isset($options['severity'])) {
                $metadata['_severity'] = $options['severity'];
            }

            // Create queued event
            $event = [
                'event' => $eventName,
                'actor' => $actor,
                'user_ip' => $options['user_ip'] ?? null,
                'metadata' => $metadata,
                'timestamp' => $timestamp,
                'retry_count' => 0,
            ];

            $this->log('Tracking event: ' . $eventName);

            if ($this->batching) {
                $this->queue[] = $event;
                $queueSize = count($this->queue);

                $this->log("Event queued. Queue size: {$queueSize}");

                if ($queueSize >= $this->batchSize) {
                    $this->flush();
                }
            } else {
                $this->sendEvents([$event]);
            }
        } catch (\Throwable $e) {
            $this->handleError('track', $e);
        }
    }

    /**
     * Flush all queued events to the server
     */
    public function flush(): void
    {
        if (empty($this->queue)) {
            $this->log('No events to flush');
            return;
        }

        $events = $this->queue;
        $this->queue = [];

        $this->log('Flushing ' . count($events) . ' events');

        try {
            $this->sendEvents($events);
        } catch (\Throwable $e) {
            $this->handleError('flush', $e);
        }
    }

    /**
     * Get the current queue size
     */
    public function getQueueSize(): int
    {
        return count($this->queue);
    }

    /**
     * Get the flush interval in seconds
     */
    public function getFlushInterval(): float
    {
        return $this->flushInterval;
    }

    /**
     * Clear all queued events without sending
     */
    public function clearQueue(): void
    {
        $this->queue = [];
        $this->log('Queue cleared');
    }

    /**
     * Shutdown the SDK gracefully
     */
    public function shutdown(): void
    {
        $this->log('Shutting down...');
        $this->flush();
        $this->log('Shutdown complete');
    }

    // ============================================
    // CONVENIENCE METHODS
    // ============================================

    /**
     * Track a login failure event
     *
     * @param string $actorId User ID
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackLoginFailed(string $actorId, array $options = []): void
    {
        $this->track('auth.login_failed', array_merge(['actor_id' => $actorId], $options));
    }

    /**
     * Track a login success event
     *
     * @param string $actorId User ID
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackLoginSuccess(string $actorId, array $options = []): void
    {
        $this->track('auth.login_success', array_merge(['actor_id' => $actorId], $options));
    }

    /**
     * Track a privilege escalation event (critical severity)
     *
     * @param string $actorId User ID
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackPrivilegeEscalation(string $actorId, array $options = []): void
    {
        $this->track('admin.privilege_escalation', array_merge([
            'actor_id' => $actorId,
            'severity' => EventSeverity::CRITICAL,
        ], $options));
    }

    /**
     * Track a sensitive data access event (high severity)
     *
     * @param string $actorId User ID
     * @param string $resource Resource accessed
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackSensitiveAccess(string $actorId, string $resource, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['resource'] = $resource;

        $this->track('data.sensitive_access', array_merge([
            'actor_id' => $actorId,
            'severity' => EventSeverity::HIGH,
            'metadata' => $metadata,
        ], $options));
    }

    /**
     * Track a bulk delete event (high severity)
     *
     * @param string $actorId User ID
     * @param int $recordCount Number of records deleted
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackBulkDelete(string $actorId, int $recordCount, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['records_deleted'] = $recordCount;

        $this->track('data.bulk_delete', array_merge([
            'actor_id' => $actorId,
            'severity' => EventSeverity::HIGH,
            'metadata' => $metadata,
        ], $options));
    }

    /**
     * Track a role change event
     *
     * @param string $actorId User ID
     * @param string $oldRole Previous role
     * @param string $newRole New role
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackRoleChanged(string $actorId, string $oldRole, string $newRole, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['old_role'] = $oldRole;
        $metadata['new_role'] = $newRole;

        $this->track('authz.role_changed', array_merge([
            'actor_id' => $actorId,
            'metadata' => $metadata,
        ], $options));
    }

    /**
     * Track an access denied event
     *
     * @param string $actorId User ID
     * @param string $resource Resource that was denied
     * @param array{actor_email?: string, user_ip?: string, metadata?: array<string, mixed>} $options
     */
    public function trackAccessDenied(string $actorId, string $resource, array $options = []): void
    {
        $metadata = $options['metadata'] ?? [];
        $metadata['resource'] = $resource;

        $this->track('authz.access_denied', array_merge([
            'actor_id' => $actorId,
            'metadata' => $metadata,
        ], $options));
    }

    // ============================================
    // PRIVATE METHODS
    // ============================================

    /**
     * @param array<int, array<string, mixed>> $events
     */
    private function sendEvents(array $events): void
    {
        if (empty($events)) {
            return;
        }

        $client = $this->getClient();

        try {
            // Single event or batch
            $isBatch = count($events) > 1;

            if ($isBatch) {
                $payload = ['events' => array_map([$this, 'eventToPayload'], $events)];
            } else {
                $payload = $this->eventToPayload($events[0]);
            }

            $response = $client->post($this->endpoint, [
                'json' => $payload,
                'timeout' => $this->timeout,
            ]);

            $result = json_decode($response->getBody()->getContents(), true);

            if ($result['success'] ?? false) {
                $acceptedMsg = $isBatch ? " ({$result['events_accepted']} accepted)" : '';
                $this->log('Successfully sent ' . count($events) . ' event(s)' . $acceptedMsg);
            } else {
                throw new \RuntimeException($result['error'] ?? 'Unknown API error');
            }
        } catch (GuzzleException $e) {
            // Re-queue events for retry
            $retryable = array_filter($events, fn($ev) => ($ev['retry_count'] ?? 0) < 3);

            if (!empty($retryable) && $this->batching) {
                $this->log('Re-queuing ' . count($retryable) . ' events for retry');
                foreach ($retryable as &$event) {
                    $event['retry_count'] = ($event['retry_count'] ?? 0) + 1;
                }
                $this->queue = array_merge($retryable, $this->queue);
            }

            throw $e;
        }
    }

    /**
     * @param array<string, mixed> $event
     * @return array<string, mixed>
     */
    private function eventToPayload(array $event): array
    {
        return [
            'event' => $event['event'],
            'actor' => $event['actor'],
            'user_ip' => $event['user_ip'],
            'metadata' => $event['metadata'],
            'timestamp' => $event['timestamp'],
        ];
    }

    private function getClient(): Client
    {
        if ($this->client === null) {
            $this->client = new Client([
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $this->apiKey,
                    'User-Agent' => 'litesoc-php-sdk/' . self::VERSION,
                ],
            ]);
        }

        return $this->client;
    }

    /**
     * Handle HTTP response errors and throw appropriate exceptions
     *
     * @throws AuthenticationException If API key is invalid (401)
     * @throws PlanRestrictedException If feature requires higher plan (403)
     * @throws RateLimitException If rate limit exceeded (429)
     * @throws LiteSOCException For other API errors
     */
    private function handleHttpError(RequestException $e): void
    {
        $response = $e->getResponse();
        $statusCode = $response?->getStatusCode() ?? 0;
        $body = $response?->getBody()?->getContents();
        $data = $body ? json_decode($body, true) : null;
        $message = $data['error'] ?? $e->getMessage();

        match ($statusCode) {
            401 => throw new AuthenticationException($message, $body, $e),
            403 => throw new PlanRestrictedException($message, $data['required_plan'] ?? null, $body, $e),
            429 => throw new RateLimitException(
                $message,
                isset($response) ? (int) $response->getHeaderLine('Retry-After') ?: null : null,
                $body,
                $e
            ),
            default => throw new LiteSOCException($message, $statusCode, $body, $e),
        };
    }

    private function handleError(string $context, \Throwable $error): void
    {
        if ($this->silent) {
            $this->log("Error in {$context}: " . $error->getMessage());
        } else {
            throw $error;
        }
    }

    private function log(string $message): void
    {
        if ($this->debug) {
            echo "[LiteSOC] {$message}\n";
        }
    }

    // ============================================
    // MANAGEMENT API METHODS (Business/Enterprise)
    // ============================================

    /**
     * Get alerts from the Management API
     *
     * Requires Business or Enterprise plan.
     *
     * @param array{
     *     severity?: string,
     *     status?: string,
     *     limit?: int,
     *     offset?: int,
     * } $filters Optional filters
     * @return array<string, mixed>
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function getAlerts(array $filters = []): array
    {
        $this->log('Fetching alerts');
        return $this->apiRequest('GET', '/alerts', $filters);
    }

    /**
     * Get a specific alert by ID
     *
     * Requires Business or Enterprise plan.
     *
     * @param string $alertId The alert ID
     * @return array<string, mixed> The alert data
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function getAlert(string $alertId): array
    {
        $this->log('Fetching alert: ' . $alertId);
        return $this->apiRequest('GET', '/alerts/' . urlencode($alertId));
    }

    /**
     * Resolve an alert
     *
     * Requires Business or Enterprise plan.
     *
     * @param string $alertId The alert ID to resolve
     * @param string $resolutionType Resolution type (e.g., 'resolved', 'false_positive')
     * @param string $notes Optional resolution notes
     * @return array<string, mixed> The updated alert
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function resolveAlert(string $alertId, string $resolutionType, string $notes = ''): array
    {
        $this->log('Resolving alert: ' . $alertId);
        return $this->apiRequest('PATCH', '/alerts/' . urlencode($alertId), [
            'status' => 'resolved',
            'resolution_type' => $resolutionType,
            'notes' => $notes,
        ]);
    }

    /**
     * Mark an alert as safe (false positive)
     *
     * Requires Business or Enterprise plan.
     *
     * @param string $alertId The alert ID to mark as safe
     * @param string $notes Optional notes explaining why it's safe
     * @return array<string, mixed> The updated alert
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function markAlertSafe(string $alertId, string $notes = ''): array
    {
        $this->log('Marking alert as safe: ' . $alertId);
        return $this->resolveAlert($alertId, 'false_positive', $notes);
    }

    /**
     * Get events from the Management API
     *
     * Requires Business or Enterprise plan.
     *
     * @param int $limit Maximum number of events to return (default: 20)
     * @param array{
     *     event?: string,
     *     actor_id?: string,
     *     severity?: string,
     *     offset?: int,
     * } $filters Optional filters
     * @return array<string, mixed>
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function getEvents(int $limit = 20, array $filters = []): array
    {
        $this->log('Fetching events');
        return $this->apiRequest('GET', '/events', array_merge(['limit' => $limit], $filters));
    }

    /**
     * Get a specific event by ID
     *
     * Requires Business or Enterprise plan.
     *
     * @param string $eventId The event ID
     * @return array<string, mixed> The event data
     * @throws AuthenticationException If API key is invalid
     * @throws PlanRestrictedException If plan doesn't support Management API
     * @throws RateLimitException If rate limit exceeded
     * @throws LiteSOCException For other API errors
     */
    public function getEvent(string $eventId): array
    {
        $this->log('Fetching event: ' . $eventId);
        return $this->apiRequest('GET', '/events/' . urlencode($eventId));
    }

    /**
     * Make an API request to the Management API
     *
     * @param string $method HTTP method
     * @param string $path API path
     * @param array<string, mixed> $data Request data (query params for GET, body for POST/PATCH)
     * @return array<string, mixed>
     */
    private function apiRequest(string $method, string $path, array $data = []): array
    {
        $client = $this->getClient();
        $url = $this->baseUrl . $path;

        try {
            $options = ['timeout' => $this->timeout];

            if ($method === 'GET' && !empty($data)) {
                $options['query'] = $data;
            } elseif (!empty($data)) {
                $options['json'] = $data;
            }

            $response = $client->request($method, $url, $options);
            $body = $response->getBody()->getContents();

            return json_decode($body, true) ?? [];
        } catch (RequestException $e) {
            $this->handleHttpError($e);
            // @codeCoverageIgnoreStart
            throw $e; // Never reached but required for static analysis
            // @codeCoverageIgnoreEnd
        }
    }
}
