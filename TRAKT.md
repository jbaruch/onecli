# Native Trakt token renewal

The Trakt connection imports an existing authorized access/refresh token pair and its OAuth client, including the exact redirect URI registered for that application. Import validates the bearer with a read-only account request. It does not spend the refresh token. The API stores the client in its encrypted app configuration and links the connection to it.

The imported bearer has no trustworthy mint timestamp, so its stored expiry is zero. The first gateway request renews it through the normal cross-instance refresh lock and encrypted token-pair persistence. Further renewals use the provider's returned lifetime. The connection stores `redirect_uri`; Trakt JSON refresh requests include it unchanged, as required by the [current token contract](https://developer.trakt.tv/?operation=postOauthToken&section=reference). Do not guess it or substitute a new callback when importing an existing grant. Agents receive the API response, not the credentials. Injection is confined to `api.trakt.tv` and supplies the bearer, client ID and API version.

## Cutover from an existing refresher

1. Verify the imported account identity before changing grants. Keep the existing encrypted OneCLI database backup and the current bridge configuration available privately.
2. Pause the old refresher before the first request using the native connection. Trakt rotates refresh tokens; two refresh owners must not run together.
3. Grant the native connection to the intended agent and verify a read-only request after the forced initial refresh. Check that the new encrypted credentials persisted, then verify another request reuses that pair.
4. Retire the generic bearer injection and the old renewal cron only after those checks. Preserve unrelated grants and cron entries.

After native renewal, the old bridge's refresh token is stale. Restoring an old token file is not a rollback; any recovery must use the latest stored pair. Never print token responses or put credentials in process arguments, source files or agent environments.

## Maintaining the HTTP identity

Trakt's edge rejects a bare HTTP-client user agent on its OAuth endpoint. The API import and gateway refresh use matching `TRAKT_USER_AGENT` constants in `packages/api/src/apps/trakt.ts` and `apps/gateway/crates/apps/src/lib.rs`. The Trakt integration maintainer checks [Chromium Stable](https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Mac&num=1) monthly, updates both values together and verifies an actual refresh. Only Trakt receives the user-agent override. OAuth refresh requests refuse redirects to keep client credentials and rotating refresh tokens on the configured endpoint.

## Deployment branch

This patch targets `deploy/nanoclaw-trakt-v2.14.0`, based on the published upstream `v2.14.0` commit `9319d08be0b1fe35be39bf899b528a8e43f93027`. It adds Trakt to that deployed version without advancing the fork's default branch. CI runs the existing full workflow for this branch too. Deploy only reviewed source, with image digests bound to that source; this patch does not publish a competing upstream release.
