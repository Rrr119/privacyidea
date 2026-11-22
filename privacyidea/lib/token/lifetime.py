# SPDX-FileCopyrightText: 2026 NetKnights GmbH <https://netknights.it>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Organization (realm) scoped token lifetime and lifecycle state.

PrivacyIDEA groups users into *realms*, which act as the tenant / organization
boundary. An organization can therefore enforce its own MFA rules by attaching
an enrollment policy (``token_lifetime``) to its realm. Everything derived from
such a policy is stored in the existing tokeninfo table, so no database
migration is needed and every existing API keeps working unchanged.

The lifecycle of a token is modeled with two independent pieces of state:

* the *expiry* derived from the enrollment policy, compared against the
  token's ``creation_date``;
* an explicit *state* (``active``/``expired``/``renewed``) that an
  administrator or a renewal workflow can move forward without touching the
  token's secret.
"""
import datetime
import logging

from dateutil.tz import tzlocal

from privacyidea.lib.policies.actions import PolicyAction
from privacyidea.lib.utils import parse_timedelta

log = logging.getLogger(__name__)

#: tokeninfo key holding the token lifetime (e.g. ``"30d"``) applied at
#: enrollment, i.e. the value of the matching organization policy.
TOKEN_LIFETIME_KEY = "token_lifetime"
#: tokeninfo key holding the lifecycle state.
LIFECYCLE_STATE_KEY = "lifecycle_state"


class LifecycleState:
    """Lifecycle states a token can be in."""
    ACTIVE = "active"
    EXPIRED = "expired"
    RENEWED = "renewed"

    ALL = frozenset({ACTIVE, EXPIRED, RENEWED})


def get_token_lifetime_policy(g, realm: str | None = None,
                              user_object=None) -> str | None:
    """Return the token lifetime configured for the given organization.

    The policy is matched in the enrollment scope. When a ``user_object`` is
    given its realm is used, otherwise the explicitly passed ``realm``.

    :param g: the application context object
    :param realm: the organization (realm) name
    :param user_object: optional user object whose realm is matched
    :return: the lifetime string (e.g. ``"90d"``) or ``None`` if no policy
        matches
    """
    # Imported locally to avoid a circular import between lib.token and
    # lib.policy at module import time.
    from privacyidea.lib.policy import Match, SCOPE

    if user_object is not None and user_object.realm:
        lifetime_policies = Match.user(
            g, scope=SCOPE.ENROLL, action=PolicyAction.TOKEN_LIFETIME,
            user_object=user_object).action_values(unique=False)
    elif realm:
        lifetime_policies = Match.realm(
            g, scope=SCOPE.ENROLL, action=PolicyAction.TOKEN_LIFETIME,
            realm=realm).action_values(unique=False)
    else:
        return None

    if not lifetime_policies:
        return None
    # Multiple policies can match (e.g. different priorities); the shortest
    # lifetime is the strictest rule and therefore the effective one.
    lifetimes = []
    for value in lifetime_policies:
        try:
            lifetimes.append((parse_timedelta(str(value)), str(value)))
        except Exception as exx:
            log.warning(f"Ignoring invalid token lifetime policy value "
                        f"{value!r}: {exx!r}")
    if not lifetimes:
        return None
    return min(lifetimes, key=lambda item: item[0])[1]


def apply_token_lifetime_policy(token, g, realm: str | None = None,
                                user_object=None) -> str | None:
    """Apply the organization's token lifetime policy to a freshly enrolled token.

    The lifetime itself is recorded on the token (``token_lifetime`` tokeninfo)
    and the lifecycle state is initialized to ``active``. The actual expiry
    timestamp is derived lazily from the token's ``creation_date`` so that a
    renewal never needs to rewrite history.

    :param token: the TokenClass object of the new token
    :param g: the application context object
    :param realm: the organization (realm) the token belongs to
    :param user_object: optional owner whose realm is matched
    :return: the lifetime string that was applied, or ``None``
    """
    if user_object is None and realm is None:
        realm = token.token.get_realms()[0] if token.token.get_realms() else None
    lifetime = get_token_lifetime_policy(g, realm=realm,
                                         user_object=user_object)
    if lifetime is None:
        return None
    token.write_tokeninfo(TOKEN_LIFETIME_KEY, lifetime)
    token.write_tokeninfo(LIFECYCLE_STATE_KEY, LifecycleState.ACTIVE)
    log.info(f"Applied token lifetime {lifetime!r} to token "
             f"{token.get_serial()}")
    return lifetime


def get_lifecycle_state(token) -> str:
    """Return the current lifecycle state of a token.

    Tokens enrolled before this feature existed have no state entry and are
    reported as :py:data:`LifecycleState.ACTIVE`, which keeps their behavior
    backwards compatible.
    """
    state = token.get_tokeninfo(LIFECYCLE_STATE_KEY)
    return state or LifecycleState.ACTIVE


def set_lifecycle_state(token, state: str) -> str:
    """Move a token to an explicit lifecycle state.

    :param token: the TokenClass object
    :param state: one of :class:`LifecycleState`
    :return: the new state
    :raises ParameterError: for an unknown state
    """
    from privacyidea.lib.error import ParameterError

    if state not in LifecycleState.ALL:
        raise ParameterError(f"Unknown lifecycle state {state!r}. Valid "
                             f"states are: {sorted(LifecycleState.ALL)}")
    token.write_tokeninfo(LIFECYCLE_STATE_KEY, state)
    return state


def get_expiry_date(token):
    """Return the expiry timestamp of a token, or ``None`` if it never expires.

    The expiry is the token's ``creation_date`` plus its recorded
    ``token_lifetime``. Tokens without a lifetime policy never expire here,
    even if an administrator also set the (older) manual validity period.

    :rtype: datetime.datetime or None
    """
    lifetime = token.get_tokeninfo(TOKEN_LIFETIME_KEY)
    if not lifetime:
        return None
    creation_date = token.get_tokeninfo("creation_date")
    if not creation_date:
        return None
    try:
        created = datetime.datetime.fromisoformat(creation_date)
        if created.tzinfo is None:
            created = created.replace(tzinfo=tzlocal())
        return created + parse_timedelta(str(lifetime))
    except Exception as exx:
        log.warning(f"Could not determine expiry date of token "
                    f"{token.get_serial()}: {exx!r}")
        return None


def is_token_expired(token, at: datetime.datetime | None = None) -> bool:
    """Check whether the policy-driven lifetime of a token has elapsed.

    An explicitly renewed token is never considered expired, and an expired
    token stays expired until it is renewed - the timestamp check alone would
    flip back and forth when the clock or creation date changes.

    :param at: override "now" (mainly for testing); defaults to the current time
    """
    state = get_lifecycle_state(token)
    if state == LifecycleState.RENEWED:
        return False
    if state == LifecycleState.EXPIRED:
        return True
    expiry = get_expiry_date(token)
    if expiry is None:
        return False
    now = at or datetime.datetime.now(tzlocal())
    return now >= expiry


def mark_expired_tokens(tokens: list | None = None,
                        at: datetime.datetime | None = None) -> list:
    """Mark all tokens whose lifetime has elapsed with the ``expired`` state.

    This is the batch entry point a periodic task or an administrator action
    can call. Only tokens carrying a lifetime policy are considered.

    :param tokens: optional list of TokenClass objects; when omitted every
        token with a ``token_lifetime`` entry is scanned
    :param at: override "now" (mainly for testing); defaults to the current time
    :return: the serials of the tokens that were marked expired
    """
    from privacyidea.lib.token import get_tokens

    expired_serials = []
    if tokens is None:
        tokens = get_tokens()
    for token in tokens:
        if not token.get_tokeninfo(TOKEN_LIFETIME_KEY):
            continue
        if get_lifecycle_state(token) == LifecycleState.RENEWED:
            continue
        if (is_token_expired(token, at=at)
                and get_lifecycle_state(token) != LifecycleState.EXPIRED):
            set_lifecycle_state(token, LifecycleState.EXPIRED)
            expired_serials.append(token.get_serial())
    return expired_serials


def renew_token(token, lifetime: str | None = None) -> datetime.datetime:
    """Renew a token, optionally with a new lifetime.

    Renewal restarts the lifetime from the current time without changing the
    token's secret, PIN or serial, so existing enrollments keep working.

    :param token: the TokenClass object
    :param lifetime: new lifetime string; when omitted the recorded one is reused
    :return: the new expiry timestamp
    :raises ParameterError: when no lifetime is given and the token has none
    """
    from privacyidea.lib.error import ParameterError

    lifetime = lifetime or token.get_tokeninfo(TOKEN_LIFETIME_KEY)
    if not lifetime:
        raise ParameterError("The token has no token lifetime configured, "
                             "so a lifetime must be passed to renew it.")
    now = datetime.datetime.now(tzlocal())
    token.write_tokeninfo("creation_date",
                          now.astimezone(datetime.UTC)
                          .isoformat(timespec="seconds"))
    token.write_tokeninfo(TOKEN_LIFETIME_KEY, lifetime)
    token.write_tokeninfo(LIFECYCLE_STATE_KEY, LifecycleState.RENEWED)
    return now + parse_timedelta(lifetime)
