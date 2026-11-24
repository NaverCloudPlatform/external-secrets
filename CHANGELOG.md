# Changelog

Releases of the NAVER Cloud fork of External Secrets Operator. Changes in
upstream code arrive with the upstream release a fork release is based on;
see the
[upstream releases](https://github.com/external-secrets/external-secrets/releases)
for those.

## v2.14.0 - 2026-11-24

Initial public release. A release of this fork carries the version of the
upstream release it is based on.

### Upstream base

- External Secrets Operator v2.14.0. Everything outside the `ncloud` provider
  is upstream code at that release, apart from the changes below. It
  includes upstream's validation of the Secret the controller writes, which
  keeps templates and manifest targets from composing service-account-token
  or bootstrap-token Secrets, and its removal of provider errors from
  conditions and events: those errors are in the controller log.
- Built with Go 1.27.4, one patch release above upstream's toolchain
  (Go 1.27.3), for the `net/http` finding
  [GO-2026-6859](https://pkg.go.dev/vuln/GO-2026-6859) that `govulncheck`
  reports on 1.27.3.
- The `e2e` and `hack/tools` modules and the requirements of the
  documentation build carry newer versions of a few dependencies than
  upstream v2.14.0 (go-jose, mongo-driver and OpenTelemetry; certifi,
  urllib3, pymdown-extensions and setuptools), for advisories reported
  against the versions upstream pins. None of them is part of the image.
- Upstream's GitHub workflows, governance and community files and
  documentation site publishing are not carried over. `docs/` is the
  upstream site source; this repository's own checks
  (`.github/workflows/ci.yml`) test what the fork adds, and build and scan
  what the image ships.

### The `ncloud` provider

- Reads Secret Manager secrets into Kubernetes Secrets (`ExternalSecret`,
  `ClusterExternalSecret`): one secret by name or by 64-character lowercase
  hexadecimal secret ID, one key of a JSON value with `property`, every key with
  `dataFrom.extract`, and many secrets with `dataFrom.find` (name prefix
  and regular expression). Stages (`previous`, `active`, `pending`) through
  `remoteRef.version`, and metadata with `metadataPolicy: Fetch`.
- Writes Kubernetes Secrets to Secret Manager (`PushSecret`,
  `ClusterPushSecret`): creates a missing secret, updates a whole JSON value
  or one key of it, and deletes what it created. A secret it creates
  carries `managed-by: external-secrets` in its memo, and a secret without
  that line is never modified.
- Deletion follows Secret Manager's lifecycle: a delete requests deletion,
  and the secret stays recoverable for the 7-day grace period, unless the
  store sets `forceDeleteWithoutRecovery: true`.
- Authentication with an access key pair from a Kubernetes Secret
  (`secretRef`), the node's Server Role (`serverRole`), or the controller's
  NKS Pod Identity (`podIdentity`), each optionally switching to a role
  through the Secure Token Service (`role`). `serverRole` and `podIdentity`
  are accepted only in a `ClusterSecretStore`. `podIdentity` needs the
  controller pod to carry the label `nks.ncloud.com/pod-identity: "true"`,
  which the release chart does not set (`podLabels`).
- Endpoints for KR (isolated-key and global-key secrets) and JPN. A secret
  is created only through the endpoint of its key's isolation boundary;
  the global-key endpoint refuses creation.
- Name-to-ID resolution is cached per endpoint and signing identity (15
  minutes for a found name, 5 minutes for a missing one); values are always
  fetched fresh.
- `GET` requests retry transient failures up to three times within a
  45-second budget per request; mutating requests are not retried, except
  for one re-send of any request signed with a temporary key that is
  refused with 401, or with a 404 carrying the API Gateway's code `300`.
- Requests are counted in `externalsecret_provider_api_calls_count` with
  `provider="Ncloud/SecretManager"`.

### Packaging

- Image `nks.kr.ncr.ntruss.com/nks/external-secrets:v2.14.0`, built with
  `PROVIDER=all_providers`, as upstream's images are: every store provider
  and generator upstream ships is registered, and `ncloud` with them. The
  chart's controller, webhook and certificate controller images default to
  its repository.
- Release asset `external-secrets-2.14.0.tgz`: the upstream chart with the
  `ncloud` CRD fields, all CRDs, and the three image tags pinned to
  `v2.14.0`. `make helm.package.release` builds it. Upstream's chart 2.14.0
  is a different chart; install this one by its release URL. Installed as
  release `external-secrets` in the namespace `external-secrets`, it uses
  the same names as the NKS add-on. The add-on does not install over it;
  the README describes the move.
- The chart marks its CRDs `helm.sh/resource-policy: keep` by default
  (`crds.annotations`), so `helm uninstall` leaves the CRDs and the
  resources created from them, where upstream's chart deletes them. A
  release upgraded with `--reuse-values` from a chart without the default
  does not get it; the README says how to check. Set the annotation to
  `null` for upstream's behavior.

### Known limitations

- Secret Manager has no tags, so `find.tags` and pushing tags are rejected.
- A value is a JSON object of string leaves, 1 to 100 entries and at most
  10,000 bytes, enforced by the service.
- During the grace period after a delete, the secret keeps its name and the
  provider refuses to create a new secret with it.
- `find` fails closed: one unreadable or disabled match, or a listing that
  keeps changing across re-reads, fails the whole `find` and keeps the last
  synced data.
