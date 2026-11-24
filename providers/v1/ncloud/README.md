# Ncloud provider: live tests

User-facing documentation lives in `docs/provider/ncloud.md`. This file covers
the opt-in tests that run against a real Ncloud account. Every one of them is
behind the `ncloud_live` build tag and the `RUN_NCLOUD_E2E=true` environment
opt-in, so `make test` never runs them.

`NCLOUD_ENDPOINT` is optional for the provider-client tests and defaults to
the KR isolated-key endpoint.

## Provider-client tests

### TestLiveClientLifecycle (creates and destroys a secret)

Run it only against an account where that mutation is intended:

```shell
RUN_NCLOUD_E2E=true \
NCLOUD_ACCESS_KEY_ID=... \
NCLOUD_SECRET_KEY=... \
make test TEST_PROVIDER=ncloud,ncloud_live TEST_PKGS=./providers/v1/ncloud/secretmanager \
  TEST_ARGS='-run TestLiveClientLifecycle -count=1'
```

The test uses a unique name, verifies create, read, property update, property
delete and full delete, and retries its bounded cleanup as a final fallback.

### TestLiveProtectionKeyDiscovery (read-only)

Checks that the account exposes a default protection key and that its
region-isolation boundary is one the provider can declare on create:

```shell
RUN_NCLOUD_E2E=true \
NCLOUD_ACCESS_KEY_ID=... \
NCLOUD_SECRET_KEY=... \
make test TEST_PROVIDER=ncloud,ncloud_live TEST_PKGS=./providers/v1/ncloud/secretmanager \
  TEST_ARGS='-run TestLiveProtectionKeyDiscovery -count=1'
```

Run this one first when bringing up a new account. It exercises the boundary
lookup independently of the lifecycle test, which cannot reach that code until
the account's Secretstore is provisioned.

## Live reconcile suite

`TestLiveReconcileLifecycle` (`pkg/controllers/ncloudlive`) runs the real
ExternalSecret and PushSecret controllers against a real account, on an API
server supplied by `envtest`. It covers what a mock cannot: credential
resolution through a `SecretStore`, a `PushSecret` creating a remote secret,
an `ExternalSecret` reading it back, `deletionPolicy: Delete` reacting to a
genuinely absent remote secret, and a `PushSecret` finalizer completing.

It needs both build tags, because provider registration is itself gated.
`make test` sets `KUBEBUILDER_ASSETS` itself:

```shell
RUN_NCLOUD_E2E=true \
NCLOUD_ACCESS_KEY_ID=... \
NCLOUD_SECRET_KEY=... \
make test TEST_PROVIDER=ncloud,ncloud_live TEST_PKGS=./pkg/controllers/ncloudlive/... \
  TEST_ARGS='-count=1 -v'
```

`NCLOUD_ENDPOINT` must be an `https://` URL, because this suite goes through
the real `SecretStore` path, where the CRD pattern and `NormalizeEndpoint` both
require one. The suite skips with an explanation when `RUN_NCLOUD_E2E` is
unset, when `NCLOUD_ENDPOINT` is not an endpoint the provider accepts, or when
`KUBEBUILDER_ASSETS` is unset, which only happens outside `make test`. Opting
in with `RUN_NCLOUD_E2E=true` and then omitting the credentials is a failure,
not a skip.

## Role switch (`TestLiveSwitchRole`)

`TestLiveSwitchRole` is read-only. It exercises the role switch against the
real Secure Token Service, which the unit tests can only imitate: whether the
request is accepted, what lifetime comes back, and whether
Secret Manager accepts the switched key for a listing. Opt in with
`NCLOUD_ROLE_NRN=nrn:...`; the key in `NCLOUD_ACCESS_KEY_ID` needs the
`switchRole` permission on that role, and `NCLOUD_STS_ENDPOINT` overrides the
public service. The node's Server Role cannot be exercised from a workstation:
the metadata endpoint exists only on a VPC server, so that path is covered by
unit tests against a local imitation of the endpoint and by the `kubectl run`
probe in the user documentation.
