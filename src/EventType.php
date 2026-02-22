<?php

declare(strict_types=1);

namespace LiteSOC;

/**
 * Pre-defined event types for LiteSOC
 *
 * These constants provide type-safe event names for common security events.
 * You can also use custom event names as strings.
 */
class EventType
{
    // Authentication events
    public const AUTH_LOGIN_SUCCESS = 'auth.login_success';
    public const AUTH_LOGIN_FAILED = 'auth.login_failed';
    public const AUTH_LOGOUT = 'auth.logout';
    public const AUTH_PASSWORD_CHANGED = 'auth.password_changed';
    public const AUTH_PASSWORD_RESET_REQUESTED = 'auth.password_reset_requested';
    public const AUTH_PASSWORD_RESET_COMPLETED = 'auth.password_reset_completed';
    public const AUTH_MFA_ENABLED = 'auth.mfa_enabled';
    public const AUTH_MFA_DISABLED = 'auth.mfa_disabled';
    public const AUTH_MFA_CHALLENGE_SUCCESS = 'auth.mfa_challenge_success';
    public const AUTH_MFA_CHALLENGE_FAILED = 'auth.mfa_challenge_failed';
    public const AUTH_SESSION_CREATED = 'auth.session_created';
    public const AUTH_SESSION_REVOKED = 'auth.session_revoked';
    public const AUTH_TOKEN_REFRESHED = 'auth.token_refreshed';

    // User events
    public const USER_CREATED = 'user.created';
    public const USER_UPDATED = 'user.updated';
    public const USER_DELETED = 'user.deleted';
    public const USER_EMAIL_CHANGED = 'user.email_changed';
    public const USER_EMAIL_VERIFIED = 'user.email_verified';
    public const USER_PHONE_CHANGED = 'user.phone_changed';
    public const USER_PHONE_VERIFIED = 'user.phone_verified';
    public const USER_PROFILE_UPDATED = 'user.profile_updated';
    public const USER_AVATAR_CHANGED = 'user.avatar_changed';

    // Authorization events
    public const AUTHZ_ROLE_ASSIGNED = 'authz.role_assigned';
    public const AUTHZ_ROLE_REMOVED = 'authz.role_removed';
    public const AUTHZ_ROLE_CHANGED = 'authz.role_changed';
    public const AUTHZ_PERMISSION_GRANTED = 'authz.permission_granted';
    public const AUTHZ_PERMISSION_REVOKED = 'authz.permission_revoked';
    public const AUTHZ_ACCESS_DENIED = 'authz.access_denied';
    public const AUTHZ_ACCESS_GRANTED = 'authz.access_granted';

    // Admin events
    public const ADMIN_PRIVILEGE_ESCALATION = 'admin.privilege_escalation';
    public const ADMIN_USER_IMPERSONATION = 'admin.user_impersonation';
    public const ADMIN_SETTINGS_CHANGED = 'admin.settings_changed';
    public const ADMIN_API_KEY_CREATED = 'admin.api_key_created';
    public const ADMIN_API_KEY_REVOKED = 'admin.api_key_revoked';
    public const ADMIN_INVITE_SENT = 'admin.invite_sent';
    public const ADMIN_INVITE_ACCEPTED = 'admin.invite_accepted';
    public const ADMIN_MEMBER_REMOVED = 'admin.member_removed';

    // Data events
    public const DATA_EXPORT = 'data.export';
    public const DATA_IMPORT = 'data.import';
    public const DATA_BULK_DELETE = 'data.bulk_delete';
    public const DATA_BULK_UPDATE = 'data.bulk_update';
    public const DATA_SENSITIVE_ACCESS = 'data.sensitive_access';
    public const DATA_DOWNLOAD = 'data.download';
    public const DATA_UPLOAD = 'data.upload';
    public const DATA_SHARED = 'data.shared';
    public const DATA_UNSHARED = 'data.unshared';

    // Security events
    public const SECURITY_SUSPICIOUS_ACTIVITY = 'security.suspicious_activity';
    public const SECURITY_RATE_LIMIT_EXCEEDED = 'security.rate_limit_exceeded';
    public const SECURITY_IP_BLOCKED = 'security.ip_blocked';
    public const SECURITY_IP_UNBLOCKED = 'security.ip_unblocked';
    public const SECURITY_ACCOUNT_LOCKED = 'security.account_locked';
    public const SECURITY_ACCOUNT_UNLOCKED = 'security.account_unlocked';
    public const SECURITY_BRUTE_FORCE_DETECTED = 'security.brute_force_detected';
    public const SECURITY_IMPOSSIBLE_TRAVEL = 'security.impossible_travel';
    public const SECURITY_GEO_ANOMALY = 'security.geo_anomaly';

    // API events
    public const API_KEY_USED = 'api.key_used';
    public const API_RATE_LIMITED = 'api.rate_limited';
    public const API_ERROR = 'api.error';
    public const API_WEBHOOK_SENT = 'api.webhook_sent';
    public const API_WEBHOOK_FAILED = 'api.webhook_failed';

    // Billing events
    public const BILLING_SUBSCRIPTION_CREATED = 'billing.subscription_created';
    public const BILLING_SUBSCRIPTION_UPDATED = 'billing.subscription_updated';
    public const BILLING_SUBSCRIPTION_CANCELLED = 'billing.subscription_cancelled';
    public const BILLING_PAYMENT_SUCCEEDED = 'billing.payment_succeeded';
    public const BILLING_PAYMENT_FAILED = 'billing.payment_failed';
    public const BILLING_INVOICE_CREATED = 'billing.invoice_created';
    public const BILLING_INVOICE_PAID = 'billing.invoice_paid';
}
