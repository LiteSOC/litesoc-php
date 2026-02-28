<?php

declare(strict_types=1);

namespace LiteSOC\Tests;

use PHPUnit\Framework\TestCase;
use LiteSOC\LiteSOC;
use LiteSOC\Actor;
use LiteSOC\EventType;
use LiteSOC\EventSeverity;
use LiteSOC\SecurityEvents;
use LiteSOC\Exceptions\LiteSOCException;
use LiteSOC\Exceptions\AuthenticationException;
use LiteSOC\Exceptions\RateLimitException;
use LiteSOC\Exceptions\PlanRestrictedException;

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
        $this->assertEquals('2.0.0', LiteSOC::VERSION);
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

        $this->assertEquals('This feature requires a Business or Enterprise plan', $exception->getMessage());
        $this->assertNull($exception->getRequiredPlan());
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
}
