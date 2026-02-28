<?php

declare(strict_types=1);

namespace LiteSOC;

/**
 * Pre-defined security event types for LiteSOC
 *
 * LiteSOC supports 26 standard events across 5 categories.
 * This class provides the same constants as EventType but with a more
 * intuitive name that matches the Node.js and Python SDK naming conventions.
 *
 * IMPORTANT: Always include user_ip for full Security Intelligence features:
 * - GeoIP enrichment (country, city, coordinates)
 * - Network Intelligence (VPN, Tor, Proxy, Datacenter detection)
 * - Threat Scoring (Low → Critical severity)
 *
 * @see EventType For the full list of event constants
 */
class SecurityEvents
{
    // ==========================================
    // AUTHENTICATION EVENTS (8)
    // ==========================================

    /** User successfully authenticated */
    public const AUTH_LOGIN_SUCCESS = 'auth.login_success';

    /** Failed login attempt */
    public const AUTH_LOGIN_FAILED = 'auth.login_failed';

    /** User logged out */
    public const AUTH_LOGOUT = 'auth.logout';

    /** Password reset completed */
    public const AUTH_PASSWORD_RESET = 'auth.password_reset';

    /** MFA enabled on account */
    public const AUTH_MFA_ENABLED = 'auth.mfa_enabled';

    /** MFA disabled on account */
    public const AUTH_MFA_DISABLED = 'auth.mfa_disabled';

    /** Session expired */
    public const AUTH_SESSION_EXPIRED = 'auth.session_expired';

    /** Authentication token refreshed */
    public const AUTH_TOKEN_REFRESHED = 'auth.token_refreshed';

    // ==========================================
    // AUTHORIZATION EVENTS (4)
    // ==========================================

    /** Access denied to resource */
    public const AUTHZ_ACCESS_DENIED = 'authz.access_denied';

    /** User role changed */
    public const AUTHZ_ROLE_CHANGED = 'authz.role_changed';

    /** Permission granted to user */
    public const AUTHZ_PERMISSION_GRANTED = 'authz.permission_granted';

    /** Permission revoked from user */
    public const AUTHZ_PERMISSION_REVOKED = 'authz.permission_revoked';

    // ==========================================
    // ADMIN EVENTS (7)
    // ==========================================

    /** New user created */
    public const ADMIN_USER_CREATED = 'admin.user_created';

    /** User account deleted */
    public const ADMIN_USER_DELETED = 'admin.user_deleted';

    /** User account suspended */
    public const ADMIN_USER_SUSPENDED = 'admin.user_suspended';

    /** Privilege escalation detected */
    public const ADMIN_PRIVILEGE_ESCALATION = 'admin.privilege_escalation';

    /** System settings changed */
    public const ADMIN_SETTINGS_CHANGED = 'admin.settings_changed';

    /** API key created */
    public const ADMIN_API_KEY_CREATED = 'admin.api_key_created';

    /** API key revoked */
    public const ADMIN_API_KEY_REVOKED = 'admin.api_key_revoked';

    // ==========================================
    // DATA EVENTS (3)
    // ==========================================

    /** Data export initiated */
    public const DATA_EXPORT = 'data.export';

    /** Bulk data deletion */
    public const DATA_BULK_DELETE = 'data.bulk_delete';

    /** Sensitive data accessed */
    public const DATA_SENSITIVE_ACCESS = 'data.sensitive_access';

    // ==========================================
    // SECURITY EVENTS (4)
    // ==========================================

    /** Suspicious activity detected */
    public const SECURITY_SUSPICIOUS_ACTIVITY = 'security.suspicious_activity';

    /** Rate limit exceeded */
    public const SECURITY_RATE_LIMIT_EXCEEDED = 'security.rate_limit_exceeded';

    /** IP address blocked */
    public const SECURITY_IP_BLOCKED = 'security.ip_blocked';

    /** Brute force attack detected */
    public const SECURITY_BRUTE_FORCE_DETECTED = 'security.brute_force_detected';

    /**
     * Get all standard security events as an array
     *
     * @return array<string, string> Event name => event value mapping
     */
    public static function all(): array
    {
        return [
            // Authentication
            'AUTH_LOGIN_SUCCESS' => self::AUTH_LOGIN_SUCCESS,
            'AUTH_LOGIN_FAILED' => self::AUTH_LOGIN_FAILED,
            'AUTH_LOGOUT' => self::AUTH_LOGOUT,
            'AUTH_PASSWORD_RESET' => self::AUTH_PASSWORD_RESET,
            'AUTH_MFA_ENABLED' => self::AUTH_MFA_ENABLED,
            'AUTH_MFA_DISABLED' => self::AUTH_MFA_DISABLED,
            'AUTH_SESSION_EXPIRED' => self::AUTH_SESSION_EXPIRED,
            'AUTH_TOKEN_REFRESHED' => self::AUTH_TOKEN_REFRESHED,
            // Authorization
            'AUTHZ_ACCESS_DENIED' => self::AUTHZ_ACCESS_DENIED,
            'AUTHZ_ROLE_CHANGED' => self::AUTHZ_ROLE_CHANGED,
            'AUTHZ_PERMISSION_GRANTED' => self::AUTHZ_PERMISSION_GRANTED,
            'AUTHZ_PERMISSION_REVOKED' => self::AUTHZ_PERMISSION_REVOKED,
            // Admin
            'ADMIN_USER_CREATED' => self::ADMIN_USER_CREATED,
            'ADMIN_USER_DELETED' => self::ADMIN_USER_DELETED,
            'ADMIN_USER_SUSPENDED' => self::ADMIN_USER_SUSPENDED,
            'ADMIN_PRIVILEGE_ESCALATION' => self::ADMIN_PRIVILEGE_ESCALATION,
            'ADMIN_SETTINGS_CHANGED' => self::ADMIN_SETTINGS_CHANGED,
            'ADMIN_API_KEY_CREATED' => self::ADMIN_API_KEY_CREATED,
            'ADMIN_API_KEY_REVOKED' => self::ADMIN_API_KEY_REVOKED,
            // Data
            'DATA_EXPORT' => self::DATA_EXPORT,
            'DATA_BULK_DELETE' => self::DATA_BULK_DELETE,
            'DATA_SENSITIVE_ACCESS' => self::DATA_SENSITIVE_ACCESS,
            // Security
            'SECURITY_SUSPICIOUS_ACTIVITY' => self::SECURITY_SUSPICIOUS_ACTIVITY,
            'SECURITY_RATE_LIMIT_EXCEEDED' => self::SECURITY_RATE_LIMIT_EXCEEDED,
            'SECURITY_IP_BLOCKED' => self::SECURITY_IP_BLOCKED,
            'SECURITY_BRUTE_FORCE_DETECTED' => self::SECURITY_BRUTE_FORCE_DETECTED,
        ];
    }

    /**
     * Check if an event type is a standard security event
     */
    public static function isValid(string $event): bool
    {
        return in_array($event, self::all(), true);
    }
}
