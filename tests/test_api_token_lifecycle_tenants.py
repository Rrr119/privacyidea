# SPDX-FileCopyrightText: 2026 NetKnights GmbH <https://netknights.it>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the organization (realm) scoped token lifetime policy.

privacyIDEA realms are the tenant / organization boundary, so three tenants
are set up:

* ``realm1`` - a tenant with a short token lifetime policy;
* ``realm2`` - a tenant with a different (longer) lifetime policy;
* ``realm3`` - a tenant without any policy, which must keep the legacy
  behavior (tokens never expire through this feature).

The tests cover the policy itself, the token lifecycle states, enforcement at
authentication time, the lifecycle API endpoints and backwards compatibility.
"""
import datetime

from dateutil.tz import tzlocal

from privacyidea.lib.policies.actions import PolicyAction
from privacyidea.lib.policy import SCOPE, set_policy, delete_policy
from privacyidea.lib.token import (init_token, remove_token, get_one_token,
                                   get_otp)
from privacyidea.lib.token.lifetime import (LifecycleState, TOKEN_LIFETIME_KEY,
                                            LIFECYCLE_STATE_KEY,
                                            get_lifecycle_state,
                                            is_token_expired,
                                            get_expiry_date,
                                            mark_expired_tokens,
                                            renew_token,
                                            set_lifecycle_state)
from privacyidea.lib.conditional_access.authentication_event_types import (
    AuthEventReason, AUTH_EVENT_REASON_KEY)
from privacyidea.lib.user import User
from .base import MyApiTestCase


class TokenLifecycleTenantTestCase(MyApiTestCase):
    """Three tenants, each exercising a different policy situation."""

    def setUp(self):
        super().setUp()
        self.authenticate()
        # Three independent organizations (tenants).
        self.setUp_user_realms()
        self.setUp_user_realm2()
        self.setUp_user_realm3()

    def tearDown(self):
        from privacyidea.lib.policy import PolicyClass
        for policy_name in ("lifetime_realm1", "lifetime_realm2"):
            if PolicyClass().list_policies(name=policy_name):
                delete_policy(policy_name)
        super().tearDown()

    def _enroll_hotp(self, serial, realm, user=None):
        param = {"serial": serial, "type": "hotp", "otpkey": self.otpkey,
                 "pin": "testpin"}
        if user:
            param["user"] = user.login
            param["realm"] = realm
        else:
            param["realm"] = realm
        with self.app.test_request_context(
                '/token/init', method='POST', data=param,
                headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(200, res.status_code, res.json)
            self.assertTrue(res.json["result"]["status"])
        return get_one_token(serial=serial)

    def _authenticate(self, serial, pin="testpin"):
        _res, _pin, otpval, _passw = get_otp(serial)
        with self.app.test_request_context(
                '/validate/check', method='POST',
                data={"serial": serial, "pass": f"{pin}{otpval}"}):
            res = self.app.full_dispatch_request()
            self.assertEqual(200, res.status_code, res.json)
            return res.json["result"]["value"]

    # ------------------------------------------------------------------
    # tenant 1: policy with a short lifetime
    # ------------------------------------------------------------------
    def test_01_tenant1_short_lifetime_enforced(self):
        set_policy(name="lifetime_realm1", scope=SCOPE.ENROLL,
                   action=f"{PolicyAction.TOKEN_LIFETIME}=1h",
                   realm=self.realm1)
        token = self._enroll_hotp("LIFE1", self.realm1,
                                  User("cornelius", self.realm1))

        # The policy value and the lifecycle state are recorded on the token.
        self.assertEqual(token.get_tokeninfo(TOKEN_LIFETIME_KEY), "1h")
        self.assertEqual(get_lifecycle_state(token), LifecycleState.ACTIVE)
        self.assertFalse(is_token_expired(token))

        expiry = get_expiry_date(token)
        self.assertIsNotNone(expiry)
        # The expiry is roughly one hour after the creation date.
        self.assertGreater(expiry, datetime.datetime.now(tzlocal()))

        # A fresh token authenticates successfully.
        self.assertTrue(self._authenticate("LIFE1"))

        # Simulate the lifetime elapsing: authentication must now fail and the
        # token must be reported as expired.
        future = datetime.datetime.now(tzlocal()) + datetime.timedelta(hours=2)
        self.assertTrue(is_token_expired(token, at=future))
        expired = mark_expired_tokens([token], at=future)
        self.assertEqual(expired, ["LIFE1"])
        self.assertEqual(get_lifecycle_state(token), LifecycleState.EXPIRED)
        self.assertFalse(self._authenticate("LIFE1"))
        # check_all records the machine-readable reason on the token.
        messages = []
        self.assertFalse(token.check_all(messages))
        self.assertIn("lifetime", messages[0].lower())
        self.assertEqual(token.auth_details[AUTH_EVENT_REASON_KEY],
                         AuthEventReason.TOKEN_LIFETIME_EXPIRED)

        # The lifecycle endpoint reports the expired state through the existing
        # API surface (no new response envelope, result.value stays a dict).
        with self.app.test_request_context(
                '/token/lifecycle/LIFE1', method='GET',
                headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(200, res.status_code, res.json)
            value = res.json["result"]["value"]
            self.assertEqual(value["serial"], "LIFE1")
            self.assertEqual(value["lifecycle_state"],
                             LifecycleState.EXPIRED)
            self.assertTrue(value["expired"])
            self.assertEqual(value["token_lifetime"], "1h")

    # ------------------------------------------------------------------
    # tenant 2: policy with a different lifetime, isolated from tenant 1
    # ------------------------------------------------------------------
    def test_02_tenant2_independent_longer_lifetime(self):
        set_policy(name="lifetime_realm1", scope=SCOPE.ENROLL,
                   action=f"{PolicyAction.TOKEN_LIFETIME}=1h",
                   realm=self.realm1)
        set_policy(name="lifetime_realm2", scope=SCOPE.ENROLL,
                   action=f"{PolicyAction.TOKEN_LIFETIME}=30d",
                   realm=self.realm2)

        token1 = self._enroll_hotp("LIFE2A", self.realm1,
                                   User("cornelius", self.realm1))
        token2 = self._enroll_hotp("LIFE2B", self.realm2,
                                   User("cornelius", self.realm2))

        # Each tenant gets its own policy value - the realms are isolated.
        self.assertEqual(token1.get_tokeninfo(TOKEN_LIFETIME_KEY), "1h")
        self.assertEqual(token2.get_tokeninfo(TOKEN_LIFETIME_KEY), "30d")

        # Two hours later, tenant 1's token is expired while tenant 2's is fine.
        in_two_hours = datetime.datetime.now(tzlocal()) + \
            datetime.timedelta(hours=2)
        self.assertTrue(is_token_expired(token1, at=in_two_hours))
        self.assertFalse(is_token_expired(token2, at=in_two_hours))

        # The batch sweep only touches the tokens that actually expired.
        expired = mark_expired_tokens([token1, token2], at=in_two_hours)
        self.assertEqual(expired, ["LIFE2A"])

    # ------------------------------------------------------------------
    # tenant 3: no policy at all - legacy behavior must be preserved
    # ------------------------------------------------------------------
    def test_03_tenant3_no_policy_keeps_legacy_behavior(self):
        set_policy(name="lifetime_realm1", scope=SCOPE.ENROLL,
                   action=f"{PolicyAction.TOKEN_LIFETIME}=1h",
                   realm=self.realm1)
        token = self._enroll_hotp("LIFE3", self.realm3,
                                  User("root", self.realm3))

        # No policy matched, so no lifetime data is written and the token does
        # not expire regardless of how far in the future we look.
        self.assertIsNone(token.get_tokeninfo(TOKEN_LIFETIME_KEY))
        self.assertIsNone(get_expiry_date(token))
        far_future = datetime.datetime.now(tzlocal()) + \
            datetime.timedelta(days=3650)
        self.assertFalse(is_token_expired(token, at=far_future))
        self.assertEqual(mark_expired_tokens([token]), [])

        # Authentication still works exactly as before the feature existed.
        self.assertTrue(self._authenticate("LIFE3"))

        # The lifecycle endpoint stays available and reports an active token.
        with self.app.test_request_context(
                '/token/lifecycle/LIFE3', method='GET',
                headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(200, res.status_code, res.json)
            value = res.json["result"]["value"]
            self.assertEqual(value["lifecycle_state"],
                             LifecycleState.ACTIVE)
            self.assertFalse(value["expired"])
            self.assertIsNone(value["expiry_date"])

    # ------------------------------------------------------------------
    # renewal workflow and explicit state transitions
    # ------------------------------------------------------------------
    def test_04_renewal_restores_an_expired_tenant_token(self):
        set_policy(name="lifetime_realm1", scope=SCOPE.ENROLL,
                   action=f"{PolicyAction.TOKEN_LIFETIME}=1h",
                   realm=self.realm1)
        token = self._enroll_hotp("LIFE4", self.realm1,
                                  User("cornelius", self.realm1))
        set_lifecycle_state(token, LifecycleState.EXPIRED)
        self.assertTrue(is_token_expired(token))

        # Renew through the API: the secret and serial are untouched, only the
        # lifecycle metadata changes.
        with self.app.test_request_context(
                '/token/lifecycle/renew/LIFE4', method='POST',
                data={}, headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(200, res.status_code, res.json)
            self.assertIn("result", res.json)

        token = get_one_token(serial="LIFE4")
        self.assertEqual(get_lifecycle_state(token),
                         LifecycleState.RENEWED)
        self.assertFalse(is_token_expired(token))
        # A renewed token authenticates again.
        self.assertTrue(self._authenticate("LIFE4"))

        # A renewal can also switch the tenant's lifetime.
        new_expiry = renew_token(token, lifetime="7d")
        self.assertEqual(token.get_tokeninfo(TOKEN_LIFETIME_KEY), "7d")
        self.assertGreater(new_expiry,
                           datetime.datetime.now(tzlocal()) +
                           datetime.timedelta(days=6))

    def test_05_explicit_lifecycle_state_transitions(self):
        token = init_token({"serial": "LIFE5", "type": "hotp",
                            "otpkey": self.otpkey},
                           tokenrealms=[self.realm3])
        # Legacy token: defaults to active.
        self.assertEqual(get_lifecycle_state(token), LifecycleState.ACTIVE)
        set_lifecycle_state(token, LifecycleState.EXPIRED)
        self.assertTrue(is_token_expired(token))
        set_lifecycle_state(token, LifecycleState.ACTIVE)
        self.assertFalse(is_token_expired(token))
        remove_token("LIFE5")

    def test_06_lifecycle_info_visible_in_generic_token_list(self):
        set_policy(name="lifetime_realm1", scope=SCOPE.ENROLL,
                   action=f"{PolicyAction.TOKEN_LIFETIME}=90d",
                   realm=self.realm1)
        self._enroll_hotp("LIFE6", self.realm1,
                          User("cornelius", self.realm1))
        # The existing /token/ endpoint keeps working and carries the new
        # tokeninfo entries, so old API clients are not affected.
        with self.app.test_request_context(
                '/token/', method='GET',
                query_string={"serial": "LIFE6"},
                headers={'Authorization': self.at}):
            res = self.app.full_dispatch_request()
            self.assertEqual(200, res.status_code, res.json)
            value = res.json["result"]["value"]
            tokens = value["tokens"]
            self.assertEqual(len(tokens), 1)
            info = tokens[0]["info"]
            self.assertEqual(info[TOKEN_LIFETIME_KEY], "90d")
            self.assertEqual(info[LIFECYCLE_STATE_KEY],
                             LifecycleState.ACTIVE)
