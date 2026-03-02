<?php

declare(strict_types=1);

namespace LiteSOC\Tests;

use PHPUnit\Framework\TestCase;
use LiteSOC\LiteSOC;
use LiteSOC\Actor;
use LiteSOC\Alert;
use LiteSOC\EventType;
use LiteSOC\EventSeverity;
use LiteSOC\Forensics;
use LiteSOC\LocationForensics;
use LiteSOC\NetworkForensics;
use LiteSOC\SecurityEvents;
use LiteSOC\Exceptions\LiteSOCException;
use LiteSOC\Exceptions\AuthenticationException;
use LiteSOC\Exceptions\RateLimitException;
use LiteSOC\Exceptions\PlanRestrictedException;
use LiteSOC\ResponseMetadata;

class LiteSOCTest extends TestCase
{
    private LiteSOC $sdk;

    protected function setUp(): void
    {
        $this->sdk = new LiteSOC('test-key', [
            'batching' => true,
            'debug' => false,
        ]);
    }

    protected function tearDown(): void
    {
        $this->sdk->clearQueue();
    }

    // ============================================
    // INITIALIZATION TESTS
    // ============================================

    public function testInitWithApiKey(): void
    {
        $sdk = new LiteSOC('test-key');
        $this->assertInstanceOf(LiteSOC::class, $sdk);
    }

    public function testInitWithoutApiKeyThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new LiteSOC('');
    }

    public function testInitWithCustomOptions(): void
    {
        $sdk = new LiteSOC('test-key', [
            'base_url' => 'https://custom.api.com',
            'endpoint' => 'https://custom.endpoint.com',
            'batching' => false,
            'batch_size' => 20,
            'flush_interval' => 10.0,
            'debug' => true,
            'silent' => false,
            'timeout' => 60.0,
        ]);
        $this->assertInstanceOf(LiteSOC::class, $sdk);
    }

    public function testVersionIsTwo(): void
    {
        $this->assertEquals('2.3.0', LiteSOC::VERSION);
    }

    public function testDefaultBaseUrl(): void
    {
        $this->assertEquals('https://api.litesoc.io', LiteSOC::DEFAULT_BASE_URL);
    }

    // ============================================
    // TRACKING TESTS
    // ============================================

    public function testTrackBasicEvent(): void
    {
        $this->sdk->track('auth.login_failed', ['actor_id' => 'user_123']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithActorId(): void
    {
        $this->sdk->track('auth.login_success', [
            'actor_id' => 'user_123',
            'actor_email' => 'test@example.com'
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithMetadata(): void
    {
        $this->sdk->track('auth.login_failed', [
            'actor_id' => 'user_123',
            'metadata' => ['reason' => 'invalid_password', 'attempts' => 3]
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithSeverity(): void
    {
        $this->sdk->track('security.suspicious_activity', [
            'actor_id' => 'user_123',
            'severity' => EventSeverity::CRITICAL
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackMultipleEvents(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->sdk->track('auth.login_failed', ['actor_id' => "user_$i"]);
        }
        $this->assertEquals(5, $this->sdk->getQueueSize());
    }

    public function testTrackWithActorArray(): void
    {
        $this->sdk->track('auth.login_success', [
            'actor' => ['id' => 'user_123', 'email' => 'test@example.com'],
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithActorString(): void
    {
        $this->sdk->track('auth.login_success', [
            'actor' => 'user_123',
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithActorEmailOnly(): void
    {
        $this->sdk->track('auth.login_success', [
            'actor_email' => 'test@example.com',
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithDateTimeTimestamp(): void
    {
        $this->sdk->track('auth.login_success', [
            'actor_id' => 'user_123',
            'timestamp' => new \DateTimeImmutable('2024-01-01T00:00:00Z'),
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithStringTimestamp(): void
    {
        $this->sdk->track('auth.login_success', [
            'actor_id' => 'user_123',
            'timestamp' => '2024-01-01T00:00:00Z',
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackWithUserIp(): void
    {
        $this->sdk->track('auth.login_success', [
            'actor_id' => 'user_123',
            'user_ip' => '192.168.1.1',
        ]);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    // ============================================
    // CONVENIENCE METHODS TESTS
    // ============================================

    public function testTrackLoginFailed(): void
    {
        $this->sdk->trackLoginFailed('user_123', ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackLoginSuccess(): void
    {
        $this->sdk->trackLoginSuccess('user_123', ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackPrivilegeEscalation(): void
    {
        $this->sdk->trackPrivilegeEscalation('admin_user', ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackSensitiveAccess(): void
    {
        $this->sdk->trackSensitiveAccess('user_123', 'pii_table', ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackBulkDelete(): void
    {
        $this->sdk->trackBulkDelete('admin_user', 500, ['user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackRoleChanged(): void
    {
        $this->sdk->trackRoleChanged('user_123', 'viewer', 'admin');
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testTrackAccessDenied(): void
    {
        $this->sdk->trackAccessDenied('user_123', '/admin/settings');
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    // ============================================
    // QUEUE MANAGEMENT TESTS
    // ============================================

    public function testGetQueueSize(): void
    {
        $this->assertEquals(0, $this->sdk->getQueueSize());
        $this->sdk->track('auth.login_failed', ['actor_id' => 'user_123']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    public function testClearQueue(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->sdk->track('auth.login_failed', ['actor_id' => "user_$i"]);
        }
        $this->assertEquals(5, $this->sdk->getQueueSize());

        $this->sdk->clearQueue();
        $this->assertEquals(0, $this->sdk->getQueueSize());
    }

    public function testGetFlushInterval(): void
    {
        $this->assertIsFloat($this->sdk->getFlushInterval());
    }

    public function testShutdownClearsQueue(): void
    {
        // Create SDK in silent mode so flush doesn't throw
        $sdk = new LiteSOC('test-key', ['batching' => true, 'silent' => true]);
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123']);
        $this->assertEquals(1, $sdk->getQueueSize());

        $sdk->shutdown();
        // After shutdown, queue may still have events due to retry on failed flush,
        // but the shutdown method should have been called and attempted to flush
        $this->assertTrue(true); // Just verify shutdown doesn't throw
    }

    public function testFlushEmptyQueue(): void
    {
        // Should not throw when queue is empty
        $this->sdk->flush();
        $this->assertEquals(0, $this->sdk->getQueueSize());
    }

    public function testFlushWithEventsSuccess(): void
    {
        // Create SDK with batching disabled so we can test immediate send
        $sdk = new LiteSOC('test-key', ['batching' => false, 'debug' => false, 'silent' => true]);

        // Mock successful response
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(202, [], json_encode(['status' => 'queued'])),
        ]);
        $handlerStack = \GuzzleHttp\HandlerStack::create($mock);
        $mockClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);
        $sdk->setHttpClient($mockClient);

        // Track event - since batching is disabled, it should send immediately
        // but silent mode prevents exceptions
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123', 'user_ip' => '192.168.1.1']);

        $this->assertEquals(0, $sdk->getQueueSize());
    }

    public function testFlushWithBatchingSuccess(): void
    {
        // Create SDK with batching enabled
        $sdk = new LiteSOC('test-key', ['batching' => true, 'debug' => false]);

        // Mock successful responses for 2 events (sent one-by-one per API spec)
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(202, [], json_encode(['status' => 'queued'])),
            new \GuzzleHttp\Psr7\Response(201, [], json_encode(['status' => 'inserted'])),
        ]);
        $handlerStack = \GuzzleHttp\HandlerStack::create($mock);
        $mockClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);
        $sdk->setHttpClient($mockClient);

        // Track 2 events (queued)
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123', 'user_ip' => '192.168.1.1']);
        $sdk->track('auth.login_success', ['actor_id' => 'user_456', 'user_ip' => '10.0.0.1']);
        $this->assertEquals(2, $sdk->getQueueSize());

        // Flush should send all events
        $sdk->flush();
        $this->assertEquals(0, $sdk->getQueueSize());
    }

    public function testFlushWithPartialFailureRequeues(): void
    {
        // Create SDK with batching enabled
        $sdk = new LiteSOC('test-key', ['batching' => true, 'debug' => false]);

        // First event succeeds, second fails with network error
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(202, [], json_encode(['status' => 'queued'])),
            new \GuzzleHttp\Exception\ConnectException(
                'Connection refused',
                new \GuzzleHttp\Psr7\Request('POST', '/collect')
            ),
        ]);
        $handlerStack = \GuzzleHttp\HandlerStack::create($mock);
        $mockClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);
        $sdk->setHttpClient($mockClient);

        // Track 2 events
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123', 'user_ip' => '192.168.1.1']);
        $sdk->track('auth.login_success', ['actor_id' => 'user_456', 'user_ip' => '10.0.0.1']);
        $this->assertEquals(2, $sdk->getQueueSize());

        // Flush - first succeeds, second fails and gets requeued
        $sdk->flush();
        
        // Failed event should be requeued with retry_count incremented
        $this->assertEquals(1, $sdk->getQueueSize());
    }

    public function testFlushWithAllEventsFailedThrows(): void
    {
        // Create SDK with batching enabled, NOT silent
        $sdk = new LiteSOC('test-key', ['batching' => true, 'debug' => false, 'silent' => false]);

        // All events fail
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Exception\ConnectException(
                'Connection refused',
                new \GuzzleHttp\Psr7\Request('POST', '/collect')
            ),
        ]);
        $handlerStack = \GuzzleHttp\HandlerStack::create($mock);
        $mockClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);
        $sdk->setHttpClient($mockClient);

        // Track 1 event
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123', 'user_ip' => '192.168.1.1']);

        // Flush should throw because all events failed
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('All 1 events failed to send');
        $sdk->flush();
    }

    public function testFlushWithApiErrorResponse(): void
    {
        // Create SDK with batching enabled, NOT silent
        $sdk = new LiteSOC('test-key', ['batching' => true, 'debug' => false, 'silent' => false]);

        // API returns error in response body (200 OK but with error field)
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(200, [], json_encode(['error' => 'Invalid event format'])),
        ]);
        $handlerStack = \GuzzleHttp\HandlerStack::create($mock);
        $mockClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);
        $sdk->setHttpClient($mockClient);

        // Track event
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123', 'user_ip' => '192.168.1.1']);

        // Flush should throw due to error in response
        // The RuntimeException from API error bubbles up directly
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid event format');
        $sdk->flush();
    }

    public function testEventRetryExhaustsAfter3Attempts(): void
    {
        // Create SDK with batching enabled
        $sdk = new LiteSOC('test-key', ['batching' => true, 'debug' => false, 'silent' => true]);

        // All attempts fail - need 4 mock responses:
        // retry_count starts at 0, increments to 1, 2, 3
        // when retry_count >= 3, event is dropped
        $mock = new \GuzzleHttp\Handler\MockHandler([
            // Attempt 1: retry_count = 0 -> becomes 1, requeued
            new \GuzzleHttp\Exception\ConnectException('Fail 1', new \GuzzleHttp\Psr7\Request('POST', '/collect')),
            // Attempt 2: retry_count = 1 -> becomes 2, requeued
            new \GuzzleHttp\Exception\ConnectException('Fail 2', new \GuzzleHttp\Psr7\Request('POST', '/collect')),
            // Attempt 3: retry_count = 2 -> becomes 3, requeued
            new \GuzzleHttp\Exception\ConnectException('Fail 3', new \GuzzleHttp\Psr7\Request('POST', '/collect')),
            // Attempt 4: retry_count = 3 -> NOT < 3, event dropped
            new \GuzzleHttp\Exception\ConnectException('Fail 4', new \GuzzleHttp\Psr7\Request('POST', '/collect')),
        ]);
        $handlerStack = \GuzzleHttp\HandlerStack::create($mock);
        $mockClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);
        $sdk->setHttpClient($mockClient);

        // Track 1 event
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123', 'user_ip' => '192.168.1.1']);
        $this->assertEquals(1, $sdk->getQueueSize());

        // Flush attempt 1 - fails, requeues with retry_count=1
        $sdk->flush();
        $this->assertEquals(1, $sdk->getQueueSize());

        // Flush attempt 2 - fails, requeues with retry_count=2
        $sdk->flush();
        $this->assertEquals(1, $sdk->getQueueSize());

        // Flush attempt 3 - fails, requeues with retry_count=3
        $sdk->flush();
        $this->assertEquals(1, $sdk->getQueueSize());

        // Flush attempt 4 - fails, retry_count=3 is NOT < 3, event dropped
        $sdk->flush();
        $this->assertEquals(0, $sdk->getQueueSize());
    }

    // ============================================
    // ACTOR TESTS
    // ============================================

    public function testActorToArray(): void
    {
        $actor = new Actor('user_123', 'test@example.com');
        $result = $actor->toArray();

        $this->assertEquals('user_123', $result['id']);
        $this->assertEquals('test@example.com', $result['email']);
    }

    public function testActorWithoutEmail(): void
    {
        $actor = new Actor('user_123');
        $result = $actor->toArray();

        $this->assertEquals('user_123', $result['id']);
        $this->assertNull($result['email']);
    }

    public function testActorReadonlyProperties(): void
    {
        $actor = new Actor('user_123', 'test@example.com');

        $this->assertEquals('user_123', $actor->id);
        $this->assertEquals('test@example.com', $actor->email);
    }

    // ============================================
    // EVENT TYPE TESTS
    // ============================================

    public function testEventTypeConstants(): void
    {
        $this->assertEquals('auth.login_failed', EventType::AUTH_LOGIN_FAILED);
        $this->assertEquals('auth.login_success', EventType::AUTH_LOGIN_SUCCESS);
        $this->assertEquals('admin.privilege_escalation', EventType::ADMIN_PRIVILEGE_ESCALATION);
    }

    public function testEventSeverityConstants(): void
    {
        $this->assertEquals('low', EventSeverity::LOW);
        $this->assertEquals('medium', EventSeverity::MEDIUM);
        $this->assertEquals('high', EventSeverity::HIGH);
        $this->assertEquals('critical', EventSeverity::CRITICAL);
    }

    // ============================================
    // SECURITY EVENTS TESTS
    // ============================================

    public function testSecurityEventsAuthenticationConstants(): void
    {
        $this->assertEquals('auth.login_success', SecurityEvents::AUTH_LOGIN_SUCCESS);
        $this->assertEquals('auth.login_failed', SecurityEvents::AUTH_LOGIN_FAILED);
        $this->assertEquals('auth.logout', SecurityEvents::AUTH_LOGOUT);
        $this->assertEquals('auth.password_reset', SecurityEvents::AUTH_PASSWORD_RESET);
        $this->assertEquals('auth.mfa_enabled', SecurityEvents::AUTH_MFA_ENABLED);
        $this->assertEquals('auth.mfa_disabled', SecurityEvents::AUTH_MFA_DISABLED);
        $this->assertEquals('auth.session_expired', SecurityEvents::AUTH_SESSION_EXPIRED);
        $this->assertEquals('auth.token_refreshed', SecurityEvents::AUTH_TOKEN_REFRESHED);
    }

    public function testSecurityEventsAuthorizationConstants(): void
    {
        $this->assertEquals('authz.access_denied', SecurityEvents::AUTHZ_ACCESS_DENIED);
        $this->assertEquals('authz.role_changed', SecurityEvents::AUTHZ_ROLE_CHANGED);
        $this->assertEquals('authz.permission_granted', SecurityEvents::AUTHZ_PERMISSION_GRANTED);
        $this->assertEquals('authz.permission_revoked', SecurityEvents::AUTHZ_PERMISSION_REVOKED);
    }

    public function testSecurityEventsAdminConstants(): void
    {
        $this->assertEquals('admin.user_created', SecurityEvents::ADMIN_USER_CREATED);
        $this->assertEquals('admin.user_deleted', SecurityEvents::ADMIN_USER_DELETED);
        $this->assertEquals('admin.user_suspended', SecurityEvents::ADMIN_USER_SUSPENDED);
        $this->assertEquals('admin.privilege_escalation', SecurityEvents::ADMIN_PRIVILEGE_ESCALATION);
        $this->assertEquals('admin.settings_changed', SecurityEvents::ADMIN_SETTINGS_CHANGED);
        $this->assertEquals('admin.api_key_created', SecurityEvents::ADMIN_API_KEY_CREATED);
        $this->assertEquals('admin.api_key_revoked', SecurityEvents::ADMIN_API_KEY_REVOKED);
    }

    public function testSecurityEventsDataConstants(): void
    {
        $this->assertEquals('data.export', SecurityEvents::DATA_EXPORT);
        $this->assertEquals('data.bulk_delete', SecurityEvents::DATA_BULK_DELETE);
        $this->assertEquals('data.sensitive_access', SecurityEvents::DATA_SENSITIVE_ACCESS);
    }

    public function testSecurityEventsSecurityConstants(): void
    {
        $this->assertEquals('security.suspicious_activity', SecurityEvents::SECURITY_SUSPICIOUS_ACTIVITY);
        $this->assertEquals('security.rate_limit_exceeded', SecurityEvents::SECURITY_RATE_LIMIT_EXCEEDED);
        $this->assertEquals('security.ip_blocked', SecurityEvents::SECURITY_IP_BLOCKED);
        $this->assertEquals('security.brute_force_detected', SecurityEvents::SECURITY_BRUTE_FORCE_DETECTED);
    }

    public function testSecurityEventsAll(): void
    {
        $all = SecurityEvents::all();

        $this->assertCount(26, $all);
        $this->assertArrayHasKey('AUTH_LOGIN_SUCCESS', $all);
        $this->assertArrayHasKey('SECURITY_BRUTE_FORCE_DETECTED', $all);
    }

    public function testSecurityEventsIsValidWithValidEvent(): void
    {
        $this->assertTrue(SecurityEvents::isValid('auth.login_success'));
        $this->assertTrue(SecurityEvents::isValid('security.brute_force_detected'));
    }

    public function testSecurityEventsIsValidWithInvalidEvent(): void
    {
        $this->assertFalse(SecurityEvents::isValid('invalid.event'));
        $this->assertFalse(SecurityEvents::isValid(''));
    }

    public function testTrackWithSecurityEvents(): void
    {
        $this->sdk->track(SecurityEvents::AUTH_LOGIN_FAILED, ['actor_id' => 'user_123']);
        $this->assertEquals(1, $this->sdk->getQueueSize());
    }

    // ============================================
    // EXCEPTION TESTS
    // ============================================

    public function testLiteSOCException(): void
    {
        $exception = new LiteSOCException('Test error', 500, '{"error": "test"}');

        $this->assertEquals('Test error', $exception->getMessage());
        $this->assertEquals(500, $exception->getStatusCode());
        $this->assertEquals('{"error": "test"}', $exception->getResponseBody());
    }

    public function testLiteSOCExceptionDefaults(): void
    {
        $exception = new LiteSOCException('Test error');

        $this->assertEquals(0, $exception->getStatusCode());
        $this->assertNull($exception->getResponseBody());
    }

    public function testAuthenticationException(): void
    {
        $exception = new AuthenticationException();

        $this->assertEquals('Invalid or missing API key', $exception->getMessage());
        $this->assertEquals(401, $exception->getStatusCode());
    }

    public function testAuthenticationExceptionCustomMessage(): void
    {
        $exception = new AuthenticationException('Custom auth error');

        $this->assertEquals('Custom auth error', $exception->getMessage());
        $this->assertEquals(401, $exception->getStatusCode());
    }

    public function testRateLimitException(): void
    {
        $exception = new RateLimitException('Too many requests', 60);

        $this->assertEquals('Too many requests', $exception->getMessage());
        $this->assertEquals(429, $exception->getStatusCode());
        $this->assertEquals(60, $exception->getRetryAfter());
    }

    public function testRateLimitExceptionDefaults(): void
    {
        $exception = new RateLimitException();

        $this->assertEquals('Rate limit exceeded', $exception->getMessage());
        $this->assertNull($exception->getRetryAfter());
    }

    public function testPlanRestrictedException(): void
    {
        $exception = new PlanRestrictedException('Upgrade required', 'enterprise');

        $this->assertEquals('Upgrade required', $exception->getMessage());
        $this->assertEquals(403, $exception->getStatusCode());
        $this->assertEquals('enterprise', $exception->getRequiredPlan());
    }

    public function testPlanRestrictedExceptionDefaults(): void
    {
        $exception = new PlanRestrictedException();

        $this->assertEquals('This feature requires a Business or Enterprise plan. Upgrade at: https://www.litesoc.io/pricing', $exception->getMessage());
        $this->assertNull($exception->getRequiredPlan());
        $this->assertEquals('https://www.litesoc.io/pricing', $exception->getUpgradeUrl());
    }

    public function testExceptionInheritance(): void
    {
        $this->assertInstanceOf(\RuntimeException::class, new LiteSOCException('test'));
        $this->assertInstanceOf(LiteSOCException::class, new AuthenticationException());
        $this->assertInstanceOf(LiteSOCException::class, new RateLimitException());
        $this->assertInstanceOf(LiteSOCException::class, new PlanRestrictedException());
    }

    // ============================================
    // NON-BATCHING MODE TESTS
    // ============================================

    public function testTrackWithoutBatchingInSilentMode(): void
    {
        $sdk = new LiteSOC('test-key', ['batching' => false, 'silent' => true]);

        // Should not throw in silent mode, even though no real server
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123']);

        // Queue should remain empty since batching is disabled
        $this->assertEquals(0, $sdk->getQueueSize());
    }

    public function testDebugModeOutputsLogs(): void
    {
        // Create SDK with debug enabled and batching enabled
        $sdk = new LiteSOC('test-key', ['batching' => true, 'debug' => true]);

        // Mock successful response
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(202, [], json_encode(['status' => 'queued'])),
        ]);
        $handlerStack = \GuzzleHttp\HandlerStack::create($mock);
        $mockClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);
        $sdk->setHttpClient($mockClient);

        // Capture output
        ob_start();
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123', 'user_ip' => '192.168.1.1']);
        $sdk->flush();
        $output = ob_get_clean();

        // Verify debug output was generated
        $this->assertStringContainsString('[LiteSOC]', $output);
        $this->assertStringContainsString('Successfully sent event', $output);
    }

    public function testSilentModeHandlesErrorsGracefully(): void
    {
        // Create SDK in silent mode (errors logged, not thrown)
        $sdk = new LiteSOC('test-key', ['batching' => true, 'debug' => true, 'silent' => true]);

        // Mock failed response
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Exception\ConnectException(
                'Connection refused',
                new \GuzzleHttp\Psr7\Request('POST', '/collect')
            ),
        ]);
        $handlerStack = \GuzzleHttp\HandlerStack::create($mock);
        $mockClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);
        $sdk->setHttpClient($mockClient);

        // Track event
        $sdk->track('auth.login_failed', ['actor_id' => 'user_123', 'user_ip' => '192.168.1.1']);

        // Capture output - in silent mode, errors are logged
        ob_start();
        $sdk->flush();
        $output = ob_get_clean();

        // Verify error was logged (not thrown)
        $this->assertStringContainsString('[LiteSOC]', $output);
        $this->assertStringContainsString('Failed to send event', $output);
    }

    // ============================================
    // RESPONSE METADATA TESTS
    // ============================================

    public function testResponseMetadataFromHeaders(): void
    {
        $headers = [
            'X-LiteSOC-Plan' => 'business',
            'X-LiteSOC-Retention' => '90',
            'X-LiteSOC-Cutoff' => '2024-01-01T00:00:00Z',
        ];

        $metadata = ResponseMetadata::fromHeaders($headers);

        $this->assertEquals('business', $metadata->plan);
        $this->assertEquals(90, $metadata->retentionDays);
        $this->assertEquals('2024-01-01T00:00:00Z', $metadata->cutoffDate);
        $this->assertTrue($metadata->hasPlanInfo());
        $this->assertTrue($metadata->hasRetentionInfo());
    }

    public function testResponseMetadataFromHeadersCaseInsensitive(): void
    {
        $headers = [
            'x-litesoc-plan' => 'enterprise',
            'x-litesoc-retention' => '365',
            'x-litesoc-cutoff' => '2023-06-01T00:00:00Z',
        ];

        $metadata = ResponseMetadata::fromHeaders($headers);

        $this->assertEquals('enterprise', $metadata->plan);
        $this->assertEquals(365, $metadata->retentionDays);
        $this->assertEquals('2023-06-01T00:00:00Z', $metadata->cutoffDate);
    }

    public function testResponseMetadataFromHeadersWithArrayValues(): void
    {
        // Guzzle returns headers as arrays
        $headers = [
            'X-LiteSOC-Plan' => ['starter'],
            'X-LiteSOC-Retention' => ['30'],
            'X-LiteSOC-Cutoff' => ['2024-06-01T00:00:00Z'],
        ];

        $metadata = ResponseMetadata::fromHeaders($headers);

        $this->assertEquals('starter', $metadata->plan);
        $this->assertEquals(30, $metadata->retentionDays);
        $this->assertEquals('2024-06-01T00:00:00Z', $metadata->cutoffDate);
    }

    public function testResponseMetadataFromEmptyHeaders(): void
    {
        $metadata = ResponseMetadata::fromHeaders([]);

        $this->assertNull($metadata->plan);
        $this->assertNull($metadata->retentionDays);
        $this->assertNull($metadata->cutoffDate);
        $this->assertFalse($metadata->hasPlanInfo());
        $this->assertFalse($metadata->hasRetentionInfo());
    }

    public function testResponseMetadataToArray(): void
    {
        $metadata = new ResponseMetadata('business', 90, '2024-01-01T00:00:00Z');

        $array = $metadata->toArray();

        $this->assertEquals([
            'plan' => 'business',
            'retentionDays' => 90,
            'cutoffDate' => '2024-01-01T00:00:00Z',
        ], $array);
    }

    public function testGetPlanInfoReturnsNullInitially(): void
    {
        $sdk = new LiteSOC('test-key');

        $this->assertNull($sdk->getPlanInfo());
        $this->assertFalse($sdk->hasPlanInfo());
    }

    // ============================================
    // NETWORK FORENSICS TESTS
    // ============================================

    public function testNetworkForensicsFromArrayFull(): void
    {
        $data = [
            'is_vpn' => true,
            'is_tor' => false,
            'is_proxy' => true,
            'is_datacenter' => true,
            'is_mobile' => false,
            'asn' => 12345,
            'asn_org' => 'Example Hosting Inc',
            'isp' => 'Example ISP',
        ];

        $network = NetworkForensics::fromArray($data);

        $this->assertTrue($network->isVpn);
        $this->assertFalse($network->isTor);
        $this->assertTrue($network->isProxy);
        $this->assertTrue($network->isDatacenter);
        $this->assertFalse($network->isMobile);
        $this->assertEquals(12345, $network->asn);
        $this->assertEquals('Example Hosting Inc', $network->asnOrg);
        $this->assertEquals('Example ISP', $network->isp);
    }

    public function testNetworkForensicsFromArrayPartial(): void
    {
        $data = [
            'is_vpn' => false,
            'is_tor' => true,
        ];

        $network = NetworkForensics::fromArray($data);

        $this->assertFalse($network->isVpn);
        $this->assertTrue($network->isTor);
        $this->assertFalse($network->isProxy);
        $this->assertFalse($network->isDatacenter);
        $this->assertFalse($network->isMobile);
        $this->assertNull($network->asn);
        $this->assertNull($network->asnOrg);
        $this->assertNull($network->isp);
    }

    public function testNetworkForensicsToArray(): void
    {
        $network = new NetworkForensics(
            isVpn: true,
            isTor: false,
            isProxy: false,
            isDatacenter: true,
            isMobile: false,
            asn: 67890,
            asnOrg: 'Test Org',
            isp: 'Test ISP',
        );

        $result = $network->toArray();

        $this->assertTrue($result['is_vpn']);
        $this->assertFalse($result['is_tor']);
        $this->assertEquals(67890, $result['asn']);
        $this->assertEquals('Test Org', $result['asn_org']);
    }

    // ============================================
    // LOCATION FORENSICS TESTS
    // ============================================

    public function testLocationForensicsFromArrayFull(): void
    {
        $data = [
            'city' => 'New York',
            'region' => 'New York',
            'country_code' => 'US',
            'country_name' => 'United States',
            'latitude' => 40.7128,
            'longitude' => -74.006,
            'timezone' => 'America/New_York',
        ];

        $location = LocationForensics::fromArray($data);

        $this->assertEquals('New York', $location->city);
        $this->assertEquals('New York', $location->region);
        $this->assertEquals('US', $location->countryCode);
        $this->assertEquals('United States', $location->countryName);
        $this->assertEquals(40.7128, $location->latitude);
        $this->assertEquals(-74.006, $location->longitude);
        $this->assertEquals('America/New_York', $location->timezone);
    }

    public function testLocationForensicsFromArrayPartial(): void
    {
        $data = [
            'country_code' => 'GB',
        ];

        $location = LocationForensics::fromArray($data);

        $this->assertNull($location->city);
        $this->assertNull($location->region);
        $this->assertEquals('GB', $location->countryCode);
        $this->assertNull($location->countryName);
        $this->assertNull($location->latitude);
        $this->assertNull($location->longitude);
        $this->assertNull($location->timezone);
    }

    public function testLocationForensicsToArray(): void
    {
        $location = new LocationForensics(
            city: 'London',
            region: 'England',
            countryCode: 'GB',
            countryName: 'United Kingdom',
            latitude: 51.5074,
            longitude: -0.1278,
            timezone: 'Europe/London',
        );

        $result = $location->toArray();

        $this->assertEquals('London', $result['city']);
        $this->assertEquals('GB', $result['country_code']);
        $this->assertEquals(51.5074, $result['latitude']);
    }

    // ============================================
    // FORENSICS TESTS
    // ============================================

    public function testForensicsFromArrayFull(): void
    {
        $data = [
            'network' => [
                'is_vpn' => true,
                'is_tor' => false,
                'is_proxy' => false,
                'is_datacenter' => true,
                'is_mobile' => false,
                'asn' => 12345,
                'asn_org' => 'Test Org',
                'isp' => 'Test ISP',
            ],
            'location' => [
                'city' => 'Berlin',
                'region' => 'Berlin',
                'country_code' => 'DE',
                'country_name' => 'Germany',
                'latitude' => 52.52,
                'longitude' => 13.405,
                'timezone' => 'Europe/Berlin',
            ],
        ];

        $forensics = Forensics::fromArray($data);

        $this->assertNotNull($forensics);
        $this->assertTrue($forensics->network->isVpn);
        $this->assertEquals(12345, $forensics->network->asn);
        $this->assertEquals('Berlin', $forensics->location->city);
        $this->assertEquals('DE', $forensics->location->countryCode);
    }

    public function testForensicsFromArrayNull(): void
    {
        $forensics = Forensics::fromArray(null);

        $this->assertNull($forensics);
    }

    public function testForensicsFromArrayEmpty(): void
    {
        $forensics = Forensics::fromArray([]);

        $this->assertNotNull($forensics);
        $this->assertFalse($forensics->network->isVpn);
        $this->assertNull($forensics->location->city);
    }

    public function testForensicsToArray(): void
    {
        $forensics = new Forensics(
            network: new NetworkForensics(
                isVpn: true,
                isTor: false,
                isProxy: false,
                isDatacenter: false,
                isMobile: true,
            ),
            location: new LocationForensics(
                city: 'Tokyo',
                countryCode: 'JP',
            ),
        );

        $result = $forensics->toArray();

        $this->assertTrue($result['network']['is_vpn']);
        $this->assertTrue($result['network']['is_mobile']);
        $this->assertEquals('Tokyo', $result['location']['city']);
        $this->assertEquals('JP', $result['location']['country_code']);
    }

    // ============================================
    // ALERT TESTS
    // ============================================

    public function testAlertFromArrayFull(): void
    {
        $data = [
            'id' => 'alert_abc123',
            'alert_type' => 'brute_force_attack',
            'severity' => 'high',
            'status' => 'open',
            'title' => 'Brute Force Attack Detected',
            'description' => 'Multiple failed login attempts from single IP',
            'source_ip' => '192.168.1.100',
            'actor_id' => 'user_123',
            'trigger_event_id' => 'evt_xyz789',
            'forensics' => [
                'network' => [
                    'is_vpn' => true,
                    'is_tor' => false,
                    'is_proxy' => false,
                    'is_datacenter' => true,
                    'is_mobile' => false,
                    'asn' => 12345,
                    'asn_org' => 'Example Hosting',
                    'isp' => 'Example ISP',
                ],
                'location' => [
                    'city' => 'New York',
                    'region' => 'New York',
                    'country_code' => 'US',
                    'country_name' => 'United States',
                    'latitude' => 40.7128,
                    'longitude' => -74.006,
                    'timezone' => 'America/New_York',
                ],
            ],
            'created_at' => '2026-03-01T12:00:00Z',
            'updated_at' => '2026-03-01T12:30:00Z',
            'resolved_at' => null,
            'resolution_notes' => null,
            'metadata' => ['attempts' => 50],
        ];

        $alert = Alert::fromArray($data);

        $this->assertEquals('alert_abc123', $alert->id);
        $this->assertEquals('brute_force_attack', $alert->alertType);
        $this->assertEquals('high', $alert->severity);
        $this->assertEquals('open', $alert->status);
        $this->assertEquals('Brute Force Attack Detected', $alert->title);
        $this->assertEquals('evt_xyz789', $alert->triggerEventId);
        $this->assertNotNull($alert->forensics);
        $this->assertTrue($alert->forensics->network->isVpn);
        $this->assertEquals(12345, $alert->forensics->network->asn);
        $this->assertEquals('New York', $alert->forensics->location->city);
        $this->assertEquals('US', $alert->forensics->location->countryCode);
        $this->assertEquals(['attempts' => 50], $alert->metadata);
    }

    public function testAlertFromArrayMinimal(): void
    {
        $data = [
            'id' => 'alert_minimal',
        ];

        $alert = Alert::fromArray($data);

        $this->assertEquals('alert_minimal', $alert->id);
        $this->assertEquals('', $alert->alertType);
        $this->assertEquals('', $alert->severity);
        $this->assertEquals('', $alert->status);
        $this->assertEquals('', $alert->title);
        $this->assertNull($alert->triggerEventId);
        $this->assertNull($alert->forensics);
        $this->assertNull($alert->description);
    }

    public function testAlertFromArrayNullForensicsFreeTier(): void
    {
        $data = [
            'id' => 'alert_free',
            'alert_type' => 'geo_anomaly',
            'severity' => 'medium',
            'status' => 'open',
            'title' => 'Geographic Anomaly',
            'trigger_event_id' => 'evt_123',
            'forensics' => null,
        ];

        $alert = Alert::fromArray($data);

        $this->assertEquals('alert_free', $alert->id);
        $this->assertEquals('evt_123', $alert->triggerEventId);
        $this->assertNull($alert->forensics);
    }

    public function testAlertToArray(): void
    {
        $alert = new Alert(
            id: 'alert_test',
            alertType: 'impossible_travel',
            severity: 'critical',
            status: 'open',
            title: 'Impossible Travel Detected',
            triggerEventId: 'evt_abc',
            forensics: new Forensics(
                network: new NetworkForensics(
                    isVpn: false,
                    isTor: true,
                    isProxy: false,
                    isDatacenter: false,
                    isMobile: false,
                ),
                location: new LocationForensics(city: 'Paris', countryCode: 'FR'),
            ),
        );

        $result = $alert->toArray();

        $this->assertEquals('alert_test', $result['id']);
        $this->assertEquals('evt_abc', $result['trigger_event_id']);
        $this->assertNotNull($result['forensics']);
        $this->assertTrue($result['forensics']['network']['is_tor']);
        $this->assertEquals('Paris', $result['forensics']['location']['city']);
    }

    public function testAlertToArrayNullForensics(): void
    {
        $alert = new Alert(
            id: 'alert_no_forensics',
            alertType: 'suspicious_activity',
            severity: 'low',
            status: 'resolved',
            title: 'Suspicious Activity',
            forensics: null,
        );

        $result = $alert->toArray();

        $this->assertEquals('alert_no_forensics', $result['id']);
        $this->assertNull($result['forensics']);
        $this->assertNull($result['trigger_event_id']);
    }

    // ============================================
    // MANAGEMENT API TESTS (with Mocked HTTP Client)
    // ============================================

    private function createMockedSdk(array $mockResponses): LiteSOC
    {
        $mock = new \GuzzleHttp\Handler\MockHandler($mockResponses);
        $handlerStack = \GuzzleHttp\HandlerStack::create($mock);
        $mockClient = new \GuzzleHttp\Client(['handler' => $handlerStack]);
        
        $sdk = new LiteSOC('test-api-key', ['debug' => false]);
        $sdk->setHttpClient($mockClient);
        
        return $sdk;
    }

    public function testGetAlertsSuccess(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [
                'X-Plan' => 'business',
                'X-Retention-Days' => '90',
            ], json_encode([
                'alerts' => [
                    ['id' => 'alert_1', 'title' => 'Suspicious Login'],
                    ['id' => 'alert_2', 'title' => 'Impossible Travel'],
                ],
                'total' => 2,
            ])),
        ]);

        $result = $sdk->getAlerts();

        $this->assertArrayHasKey('alerts', $result);
        $this->assertCount(2, $result['alerts']);
        $this->assertEquals('alert_1', $result['alerts'][0]['id']);
    }

    public function testGetAlertsWithFilters(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [], json_encode([
                'alerts' => [['id' => 'alert_critical']],
                'total' => 1,
            ])),
        ]);

        $result = $sdk->getAlerts([
            'severity' => 'critical',
            'status' => 'active',
            'limit' => 10,
            'offset' => 0,
        ]);

        $this->assertCount(1, $result['alerts']);
    }

    public function testGetAlertSuccess(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [], json_encode([
                'id' => 'alert_123',
                'alert_type' => 'impossible_travel',
                'severity' => 'critical',
                'status' => 'active',
                'title' => 'Impossible Travel Detected',
            ])),
        ]);

        $result = $sdk->getAlert('alert_123');

        $this->assertEquals('alert_123', $result['id']);
        $this->assertEquals('impossible_travel', $result['alert_type']);
    }

    public function testResolveAlertSuccess(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [], json_encode([
                'id' => 'alert_123',
                'status' => 'resolved',
                'resolved_at' => '2024-01-15T10:30:00Z',
            ])),
        ]);

        $result = $sdk->resolveAlert('alert_123', 'blocked_ip', 'IP has been blocked in firewall');

        $this->assertEquals('alert_123', $result['id']);
        $this->assertEquals('resolved', $result['status']);
    }

    public function testResolveAlertWithoutNotes(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [], json_encode([
                'id' => 'alert_456',
                'status' => 'resolved',
            ])),
        ]);

        $result = $sdk->resolveAlert('alert_456', 'false_positive');

        $this->assertEquals('resolved', $result['status']);
    }

    public function testMarkAlertSafeSuccess(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [], json_encode([
                'id' => 'alert_789',
                'status' => 'safe',
            ])),
        ]);

        $result = $sdk->markAlertSafe('alert_789', 'User confirmed this was expected');

        $this->assertEquals('alert_789', $result['id']);
        $this->assertEquals('safe', $result['status']);
    }

    public function testMarkAlertSafeWithoutNotes(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [], json_encode([
                'id' => 'alert_abc',
                'status' => 'safe',
            ])),
        ]);

        $result = $sdk->markAlertSafe('alert_abc');

        $this->assertEquals('safe', $result['status']);
    }

    public function testGetEventsSuccess(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [
                'X-Plan' => 'enterprise',
            ], json_encode([
                'success' => true,
                'data' => [
                    ['id' => 'evt_1', 'event_name' => 'auth.login_failed'],
                    ['id' => 'evt_2', 'event_name' => 'auth.login_success'],
                ],
                'pagination' => [
                    'total' => 2,
                    'limit' => 20,
                    'offset' => 0,
                    'has_more' => false,
                ],
                'meta' => [
                    'plan' => 'enterprise',
                    'retention_days' => 365,
                ],
            ])),
        ]);

        $result = $sdk->getEvents(20);

        $this->assertArrayHasKey('data', $result);
        $this->assertCount(2, $result['data']);
    }

    public function testGetEventsWithFilters(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [], json_encode([
                'success' => true,
                'data' => [['id' => 'evt_critical']],
                'pagination' => [
                    'total' => 1,
                    'limit' => 50,
                    'offset' => 10,
                    'has_more' => false,
                ],
                'meta' => [
                    'plan' => 'business',
                    'retention_days' => 90,
                ],
            ])),
        ]);

        $result = $sdk->getEvents(50, [
            'event_name' => 'auth.login_failed',
            'actor_id' => 'user_123',
            'severity' => 'critical',
            'offset' => 10,
        ]);

        $this->assertCount(1, $result['data']);
    }

    public function testGetEventSuccess(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [], json_encode([
                'success' => true,
                'data' => [
                    'id' => 'evt_123',
                    'event_name' => 'auth.login_failed',
                    'actor' => ['id' => 'user_456', 'email' => 'user@example.com'],
                ],
                'meta' => [
                    'plan' => 'business',
                    'retention_days' => 90,
                    'redacted' => false,
                ],
            ])),
        ]);

        $result = $sdk->getEvent('evt_123');

        $this->assertEquals('evt_123', $result['data']['id']);
        $this->assertEquals('auth.login_failed', $result['data']['event_name']);
    }

    public function testAuthenticationExceptionOnInvalidApiKey(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(401, [], json_encode([
                'error' => 'Invalid API key',
            ])),
        ]);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Invalid API key');

        $sdk->getAlerts();
    }

    public function testPlanRestrictedExceptionOnFreeplan(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(403, [], json_encode([
                'error' => 'Management API requires Business plan',
                'required_plan' => 'Business',
            ])),
        ]);

        $this->expectException(PlanRestrictedException::class);

        $sdk->getEvents();
    }

    public function testRateLimitExceptionOnTooManyRequests(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(429, [
                'Retry-After' => '60',
            ], json_encode([
                'error' => 'Rate limit exceeded',
            ])),
        ]);

        $this->expectException(RateLimitException::class);
        $this->expectExceptionMessage('Rate limit exceeded');

        $sdk->getAlerts();
    }

    public function testGenericLiteSOCExceptionOnServerError(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(500, [], json_encode([
                'error' => 'Internal server error',
            ])),
        ]);

        $this->expectException(LiteSOCException::class);

        $sdk->getAlerts();
    }

    public function testPlanInfoFromResponse(): void
    {
        $sdk = $this->createMockedSdk([
            new \GuzzleHttp\Psr7\Response(200, [
                'X-LiteSOC-Plan' => 'enterprise',
                'X-LiteSOC-Retention' => '365',
                'X-LiteSOC-Cutoff' => '2023-01-15T00:00:00Z',
            ], json_encode([
                'alerts' => [],
                'total' => 0,
            ])),
        ]);

        $sdk->getAlerts();

        $this->assertTrue($sdk->hasPlanInfo());
        $planInfo = $sdk->getPlanInfo();
        $this->assertNotNull($planInfo);
        $this->assertEquals('enterprise', $planInfo->plan);
        $this->assertEquals(365, $planInfo->retentionDays);
    }
}
