<!-- Modified from https://github.com/external-secrets/external-secrets by NAVER Cloud Corp. -->

# External Secrets Operator

Kubernetes operator that synchronizes secrets from external providers (AWS Secrets Manager, Vault, GCP Secret Manager, Azure Key Vault, etc.) into Kubernetes Secrets.

## Build and Test

Use `make` targets — refer to the Makefile for available commands. Do not run `go test`, `golangci-lint`, or `helm` directly.

You must run `make test && make check-diff` before the PR is ready. (See also section Non-Obvious patterns for more explanations about the tests)

## Project Layout

Single binary built from `main.go`. The **controller** reconciles ExternalSecrets into K8s Secrets. The **webhook** (validates and defaults CRDs) and **certcontroller** (manages webhook TLS) are subcommands registered via `rootCmd.AddCommand()`.

Multi-module repo: `apis/`, `runtime/`, `e2e/`, and each `providers/v1/*/` have their own `go.mod`.

## Non-Obvious Patterns

- `make reviewable` is the gate for PRs. Run it, not individual checks.
- Helm chart is the source of truth for deploy manifests. `make manifests` generates static YAML from it.
- For SHA-only image pins in `.updatecli.d/docker.yaml`, resolve the digest from `{{ source "<image>_version" }}` so the human-readable full-tag comment and the digest refer to the same release. Update both targets when adding an image.
- Provider docs `{% include %}` reusable YAML snippets from `docs/snippets/` (`macros` plugin). AWS authentication is documented once on the standalone `docs/provider/aws-access.md` page; the per-service pages (`aws-secrets-manager.md`, `aws-parameter-store.md`) link to it rather than transcluding it.
- The chart has snapshot tests as well (`deploy/charts/external-secrets/tests/__snapshot__`), and a passing `matchSnapshot` is weaker than it looks: helm-unittest inserts a missing entry silently even without `-u`, and the 1.0.0 release upstream still pins passed every mismatch. `make helm.test.update` therefore deletes the snapshots and regenerates them from a fresh render, and `make check-diff` diffs the result, so drift shows up as a changed file rather than as a failed assertion.
- CRD tests use snapshot testing. Run `make test.crds.update` to update snapshots after CRD changes. The suite (`cty`) renders a sample instance with every string field, optional ones included, set to the literal `string`, so a new string field with a `Pattern` marker fails validation there no matter what the pattern is. Add the field's `in body should match` error to `ignoreErrors` in `tests/<kind>_test.yaml`; that entry suppresses the sample's error and is not coverage of the pattern, which belongs in a Go test that reads the generated CRD.
- `make update-deps` updates dependencies across all modules at once.
- Add a `git notes add HEAD` entry on every non-trivial commit. Record key design decisions, trade-offs, and gotchas. Queryable via `git notes show <sha>`.
- If you discover a non-obvious pattern while implementing, add it here before the PR is merged. Keep entries general — applicable across the codebase, not specific to one provider or feature.
- Never edit `zz_generated.*` files by hand. They are owned by controller-gen. Modify the source types and run `make generate` (included in `make reviewable`).
- After everything is committed - **ALWAYS RUN `make check-diff`** - this is the first step where PRs fall apart that LLMs forget - there are a lot of generated code outside of the main `make reviewable` spec like helm chart tests, docs, etc.
- The `go` directive in every `go.mod` is the minimum Go version consumers must use, so keep it at a `.0` patch (`go 1.27.0`). To build with a newer Go release (e.g. for a CVE fix), bump `toolchain` in the root `go.mod` only; `actions/setup-go` reads it, and importers ignore it. `make update-deps` bumps it to the latest patch of the same minor; Dependabot cannot. `make lint` enforces this via `hack/check-go-directive.sh`.
- `make check-diff` runs `make reviewable`, which shells out to tools a Go toolchain does not bring: `manifests`, `helm.schema.update` and `helm.test.update` need helm, `docs` needs docker, and `tf.fmt` (the LAST target in `reviewable`) needs terraform. On macOS `hack/helm.generate.sh` (run by `manifests`) also calls GNU sed as `gsed` (`brew install gnu-sed`); without it the run stops in `helm.generate` and leaves the split CRD files it was rewriting under `deploy/charts/external-secrets/templates/crds/`. Without terraform the run ends in `bash: line 1: terraform: command not found`, `make: *** [tf.fmt] Error 127` after every other prerequisite of `reviewable` has run, and `tf.fmt` being a prerequisite means two steps never run at all: `reviewable`'s own recipe (the per-module `GOWORK=off go mod tidy` loops) and `check-diff`'s `git status --porcelain` test. Nothing has checked the tree, so that is not a green result and must not be reported as one. When the change touches no `.tf` file (check with `git diff --name-only main...HEAD | grep '\.tf$'`), run `make -o tf.fmt check-diff` instead: `-o` treats `tf.fmt` as already made, so everything else, the tidy loops and the clean-tree test included, still runs, and say that `tf.fmt` was the step left out. Where CI runs `check-diff`, it installs both helm and terraform itself; the public repository's CI does not run `check-diff`, so there the local run is the only one.
- `make test` rebuilds `go.work` (via `make go-work`) every run. The target pins the workspace to the root `go.mod`'s `go` directive on purpose: `go work init` otherwise stamps the version of whatever toolchain is on PATH, and a workspace newer than the modules makes every later `go` command refuse it. The symptom is `make lint` failing in **all** modules right after a successful `make test`, with `go.work requires go >= X` or a `could not load export data ... export data version` mismatch from golangci-lint, neither of which names `go.work`. Do not add a `toolchain` directive to a module other than the root to work around a local Go version; `hack/check-go-directive.sh` refuses it. The same trap runs the other way after bumping the root `go` directive: the stale `go.work` is now older than the root module, and every `go` command, `make generate` and `make check-diff` included, fails with `module .. listed in go.work file requires go >= X, but go.work lists go Y`. Run `make go-work` first; `make test` does not help here, because `test: generate envtest` runs `generate` before its recipe reaches `$(MAKE) go-work`, so it fails the same way. A third go.work effect is silent: `go mod tidy` run inside the workspace treats a checksum that any other workspace module's go.sum already holds as present and does not write it, so after a dependency bump every module except the one bumped keeps an incomplete go.sum, local builds still pass through the shared workspace, and CI, which has no go.work, fails with `missing go.sum entry for go.mod file`. The Makefile's tidy loop runs with `GOWORK=off` for this reason; do the same for any tidy run by hand. A fourth form appears in a git worktree nested inside the main checkout (for example under `.claude/worktrees/`): the worktree has no `go.work` of its own, so Go walks up to the main checkout's, whose relative `use` paths do not cover the worktree. `make generate` then fails with `directory prefix . does not contain modules listed in go.work`, and `make go-work` refuses with `go.work already exists`. Run the checks there with `GOWORK=off`, which is what CI does.
- Narrow a local test run with `make test TEST_PKGS=./path/... TEST_ARGS='-run TestName'` rather than calling `go test`, so the build tags and envtest assets stay the ones CI uses.
- There is a second, separate way `make lint` fails, and `go.work` is correct in this one: the Go on PATH is newer than the root `go.mod`'s `toolchain` directive. Fix it by rerunning with that toolchain, e.g. `GOTOOLCHAIN=go1.27.4 make lint`. It can surface as `could not load export data ... export data version N is greater than maximum supported version M` naming a stdlib package such as `internal/goarch`, or as `panic: file requires newer Go version go1.X`, and neither names anything in this repo. `bin/golangci-lint` is downloaded at `GOLANGCI_LINT_VERSION` and again whenever the Makefile changes, so deleting it is never needed. Tell this apart from the `go.work` trap by reading `go.work`'s first line: if it already matches `go.mod`, it is this one.
- The chart directory is not installable as checked out. `deploy/charts/external-secrets/templates/crds/*.yaml` is generated by `make helm.generate` and ignored by `.gitignore`, so `helm install deploy/charts/external-secrets` from a fresh checkout installs no CRDs, and it also needs `helm dependency build` for the `bitwarden-sdk-server` subchart. Anything that installs, packages or vendors the chart goes through a make target that depends on `helm.generate` (`helm.build`, `helm.package.release`) or runs `make helm.generate` first. Rendering a fresh checkout first fails on the missing dependency, and after `helm dependency build` it succeeds with zero CRDs, which nothing flags.

## Adding a Provider

A provider is its own Go module under `providers/v1/<name>/` with no build tags on the package itself.
Build tags live in `pkg/register/<name>.go`.

### API types

- New spec goes in `apis/externalsecrets/v1/secretstore_<name>_types.go`.
- Add a one-line slot to the discriminator union in `apis/externalsecrets/v1/secretstore_types.go`
  (the `SecretStoreProvider` struct). The JSON tag is the provider name; `apis/externalsecrets/v1/provider_schema.go`
  resolves it from the first JSON key of the marshaled union.
- Auth: nested `*<Name>Auth` struct. Multi-method auth uses `+kubebuilder:validation:MaxProperties=1`. Selector types
  are `esmeta.SecretKeySelector` and `esmeta.ServiceAccountSelector`.
- CA: include `CABundle []byte` and `CAProvider *CAProvider` if the backend speaks TLS.
- v1 API is frozen by default. Net-new provider slots are fine

### Runtime helpers (use these, do not roll your own)

- `runtime/esutils/resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, ref)` for credential resolution. It enforces
  `ClusterSecretStore` vs `SecretStore` namespace scoping. Pass `store.GetKind()` and the ES namespace.
- `runtime/esutils.FetchCACertFromSource(ctx, esutils.CreateCertOpts{...})` for CA bundles.
- `runtime/esutils.ValidateSecretSelector` / `ValidateReferentSecretSelector` / `ValidateServiceAccountSelector` for spec validation.
- `runtime/esutils/metadata` for parsing `PushSecretMetadata` into a typed spec.
- `runtime/metrics.ObserveAPICall` for provider API metrics. Keep provider and call label constants in the provider package.

### `SecretsClient` contract

Defined at `apis/externalsecrets/v1/provider.go`. All eight methods are mandatory; `Close` may be a no-op.

- Return `esv1.NoSecretErr` from `GetSecret` when the secret is missing. The reconciler depends on this for `deletionPolicy`.
- Set `Capabilities()` honestly: `SecretStoreReadOnly`, `SecretStoreWriteOnly`, or `SecretStoreReadWrite`. Read-only
  providers still implement Push/Delete but return a sentinel error! Do _NOT_ return `nil`!
- `gjson` is the conventional path extractor for `ref.Property` on JSON payloads.

### Caching (skip unless construction is expensive)

- Per-Provider client cache: `runtime/cache.Must[T](size, cleanup)`. Keyed by `cache.Key{Name, Namespace, Kind}`,
  versioned by `store.GetObjectMeta().ResourceVersion`. Use this for OIDC, vault leases, token exchange, etc. Default to no cache.
- Per-secret cache (in the SecretsClient): `expirable.LRU[string, []byte]` with a user-facing `CacheConfig{TTL, MaxSize}`
  field on the spec.

### Feature flags

Pipeline: helm value to deployment `extraArgs` to cmd flag to `feature.Register` to `Initialize()`.

- Register flags from the provider's `init()` using `runtime/feature.Feature{Flags, Initialize}`.
- `cmd/controller/root.go` collects them and runs `Initialize` after manager startup.
- `Initialize` returns nothing, so a flag whose value needs checking should be a `pflag.Value` whose `Set` does the check; cobra then refuses a bad value at parse time like any other malformed flag, instead of the provider panicking or every store failing later.
- Helm wiring is `extraArgs` in `deploy/charts/external-secrets/values.yaml`, rendered by `templates/deployment.yaml`.
  Out-of-process SDKs (e.g. bitwarden) ship as a sidecar subchart.

### Registration

Provider package exports three symbols: `NewProvider() esv1.Provider`, `ProviderSpec() *esv1.SecretStoreProvider`,
`MaintenanceStatus() esv1.MaintenanceStatus`. `ProviderSpec()` must set exactly one field on the union.

Registration lives in `pkg/register/<name>.go`:

```go
//go:build <name> || all_providers
package register

import (
    esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
    foo "github.com/external-secrets/external-secrets/providers/v1/foo"
)

func init() {
    esv1.Register(foo.NewProvider(), foo.ProviderSpec(), foo.MaintenanceStatus())
}
```

Maintenance values: `MaintenanceStatusMaintained`, `NotMaintained`, `Deprecated` (`apis/externalsecrets/v1/provider_schema_maintenance.go`).

### Wiring

- Add `providers/v1/<name> => ./providers/v1/<name>` to root `go.mod` (alphabetized).
- `Makefile` honors `PROVIDER ?= all_providers` and passes it as `go build -tags`.

### Documentation

- Write `docs/provider/<slug>.md`. Conventional sections: intro, Authentication or Store Configuration, External Secret Spec / GetSecret, optional PushSecret.
- YAML examples live in `docs/snippets/<name>-secret-store.yaml`, `<name>-external-secret.yaml`, `<name>-push-secret.yaml`.
  Pull them in via `{% include '<name>-secret-store.yaml' %}`.
- Add nav entry to the `Provider:` block in `hack/api-docs/mkdocs.yml`. Order is historical; append at the bottom.

## Adding a Generator

A generator is its own Go module under `generators/v1/<name>/`. Generators are **v1alpha1 only** and are
**unconditionally compiled** into the binary (no build tags, unlike providers).

The repo ships a scaffold: `esoctl bootstrap generator --name <Name>` (`cmd/esoctl/generator/bootstrap.go`).
Run it first; the manual steps below are the audit checklist for what it produced and what it skipped.

### What `esoctl bootstrap generator` wires for you

- Creates `apis/generators/v1alpha1/types_<pkg>.go` (CRD types).
- Creates `generators/v1/<pkg>/{<pkg>.go,<pkg>_test.go,go.mod,go.sum}` from templates in `cmd/esoctl/generator/templates/`.
- Patches `pkg/register/generators.go` with the import and `genv1alpha1.Register(<pkg>.Kind(), <pkg>.NewGenerator())`.
- Patches `apis/generators/v1alpha1/types_cluster.go`: enum value, `GeneratorKind<Name>` const, and a field on
  `GeneratorSpec` (the discriminator union).
- Adds the `replace` directive to root `go.mod`.
- Patches `runtime/esutils/resolvers/generator.go` `clusterGeneratorToVirtual` switch.
- Patches `apis/generators/v1alpha1/register.go` (`<Name>Kind` var + `SchemeBuilder.Register`).
- Patches `apis/externalsecrets/v1/externalsecret_types.go` `GeneratorRef.Kind` enum. This is the one v1 enum write the
  bootstrap performs; it is documentation-class, not behavioral.

What it does **NOT** do: ClusterRole RBAC, mkdocs nav, docs, snippets, helm.

### API types

- All generators live in `apis/generators/v1alpha1/`. No v1beta1, no v1.
- Per-generator file is `types_<name>.go`. Standard shape: `<Name>Spec`, `<Name>` (TypeMeta + ObjectMeta + Spec), `<Name>List`.
  Most generators have no Status field.
- Standard markers: `+kubebuilder:object:root=true`, `+kubebuilder:storageversion`, `+kubebuilder:subresource:status`,
  `+kubebuilder:metadata:labels="external-secrets.io/component=controller"`,
  `+kubebuilder:resource:scope=Namespaced,categories={external-secrets, external-secrets-generators}`.
- All concrete generators are `scope=Namespaced`. Cluster-scoped use is delivered by the single `ClusterGenerator`
  umbrella type (`apis/generators/v1alpha1/types_cluster.go`) which embeds a `GeneratorSpec` discriminator union with
  `MaxProperties=1` / `MinProperties=1`. Do **NOT** write a `Cluster<Name>` type. Add one field to that union and one
  `GeneratorKind` enum value.

### `Generator` interface

Defined at `apis/generators/v1alpha1/generator_interfaces.go`. Two methods:

```go
Generate(ctx, obj *apiextensions.JSON, kube client.Client, namespace string) (map[string][]byte, GeneratorProviderState, error)
Cleanup(ctx, obj *apiextensions.JSON, status GeneratorProviderState, kube client.Client, namespace string) error
```

- Spec arrives as raw `apiextensions.JSON`. YAML-unmarshal it inside `Generate`.
- Returns the full `map[string][]byte` of generated keys at once. There is no per-key `GetSecret`.
- `GeneratorProviderState` is `*apiextensions.JSON`, an opaque blob persisted between `Generate` and `Cleanup`.
- `Cleanup` MUST be idempotent.

### Runtime helpers

- `runtime/esutils/resolvers.SecretKeyRef(ctx, kube, resolvers.EmptyStoreKind, ns, ref)` for credential refs. Generators
  pass `EmptyStoreKind` because they have no SecretStore; namespace scoping does not apply.
- `runtime/esutils.FetchServiceAccountToken` for SA-token auth, `esutils.ExtractJWTExpiration` for JWT parsing.
- AWS-family generators reuse the provider's auth path:
  `awsauth "github.com/external-secrets/external-secrets/providers/v1/aws/auth"` then `awsauth.NewGeneratorSession(...)`.
  Vault generator imports `providers/v1/vault` and calls `provider.NewGeneratorClient`. Cross-module imports of providers
  are normal; wire via `replace` in the generator's own `go.mod`.

### State and lifecycle

Stateless **by default**. Return `nil` for `GeneratorProviderState` from `Generate` and a no-op `Cleanup` (uuid, password,
ecr, sts all do this).

Stateful generators return a non-nil state. `runtime/statemanager` persists it to a `GeneratorState` CR
(`apis/generators/v1alpha1/generator_state_types.go`). The `generatorstate` controller runs a finalizer that calls
`Cleanup` on deletion. If state persistence fails post-Generate, statemanager invokes Cleanup as rollback; if Cleanup
itself errors, it creates a `GeneratorState` with an immediate `GarbageCollectionDeadline`.

No generator currently uses `runtime/cache.Must` style client caching.

### Registration

Generator package exports two symbols: `NewGenerator() genv1alpha1.Generator` and `Kind() string`. Registration lives in
`pkg/register/generators.go`:

```go
import (
    genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
    foo "github.com/external-secrets/external-secrets/generators/v1/foo"
)

func init() {
    genv1alpha1.Register(foo.Kind(), foo.NewGenerator())
}
```

`Register` panics on duplicate kinds. Scheme registration is separate, in `apis/generators/v1alpha1/register.go`:
`<Name>Kind = reflect.TypeFor[<Name>]().Name()` and `SchemeBuilder.Register(&<Name>{}, &<Name>List{})`.

The runtime resolver (`runtime/esutils/resolvers/generator.go`) loads the typed object via the scheme then dispatches to
the registered `Generator` by kind. ClusterGenerator goes through `clusterGeneratorToVirtual` which materializes a
synthetic namespaced object from the union spec; every generator must have a case there.

### Feature flags

No precedent. None of the existing generators register `runtime/feature` flags. If you need one, follow the provider
pattern, but expect to be the first.

### Documentation

- Generator docs live at `docs/api/generator/<name>.md`.
- YAML snippets in `docs/snippets/<name>-...yaml`, transcluded via `{% include %}` (macros plugin).
- Nav entry goes under `Reference: -> API: -> Generators:` in `hack/api-docs/mkdocs.yml`. Append at the bottom.

### Manual checklist after bootstrap

- ClusterRole rules in `deploy/charts/external-secrets/templates/rbac.yaml` for any new resources the generator reads.
- Docs page + snippets.
- mkdocs nav entry.
- After adding the module to `go.work`, run `go work use` to reconcile the `go` directive version.

## Allowed agent actions

Agents may:

- inspect the repository,
- explain code,
- propose changes,
- edit local files,
- write tests,
- update documentation,
- run checks,
- prepare a local diff for human review,
- ...

in order to assist humans.

## Blocked actions

Agents must not:

- create pull requests,
- push branches,
- publish releases,
- upload packages,
- change repository settings,
- change permissions,
- rotate credentials,
- modify secrets,
- perform external write actions.

If asked to perform a blocked action, do not perform it. Instead, create a local file named AGENT_BLOCKED_ACTION.md containing:

1. the requested action,
2. why the action is blocked,
3. the local work that was completed, if any,
4. the recommended manual steps a human contributor should take next.

## Work verification checklist

Before presenting work as complete, verify:

- [ ] the intent is documented,
- [ ] the diff is minimal and surgical (must not touch adjacent comments or code unrelated to the work),
- [ ] the relevant tests were run (see build and test section),
- [ ] the documentation was updated.

If validation could not be completed, state it explicitly and explain why.

## Fork notes

This fork ships the Ncloud provider. The entries below are specific to it and kept apart from the upstream sections above, so an upstream rebase does not conflict with them.

- The shipped image is built with `PROVIDER=all_providers`, the default as upstream's is, so it registers every upstream provider and the Ncloud one. `PROVIDER=ncloud` builds a binary that registers only the Ncloud provider and upstream's always-built `kubernetes` one; the admission webhook of such a build rejects stores for any other provider.
- A fork release carries the version of the upstream release it is based on (`v2.14.0` is upstream v2.14.0 plus the provider and the changes the README lists under "Changes from upstream"), and a later release on the same base raises the patch number. Tag a release whose number is ahead of its base's (a later release on the same base, or the first one on a new base when the fork has already used that base's number) only while the base is still upstream's latest patch release of that minor, and check that right before tagging (`git ls-remote --tags` on upstream's repository shows them); once upstream has published a later one, move to the latest one first, so a fork release never carries a number that upstream has already used for a release other than its base. A release that carries its base's own number needs no such check. If upstream publishes that patch number later, a fork release based on it takes the patch number after the fork's latest, and the README's table of bases is what tells the two apart. The tag of the first release on a base therefore has the name of an upstream tag, and a later one can have: a clone that fetched upstream's tags holds upstream's commit under that name, and `git checkout vX.Y.Z` and `git describe`, which the Makefile's `VERSION` reads, then see the wrong one. Name an upstream commit by its hash, or fetch upstream's tags into a namespace of their own (`git fetch <upstream> 'refs/tags/*:refs/upstream-tags/*' --no-tags`). `Chart.yaml` does not hold the release version either: it is upstream's file, which at an upstream release tag still holds the version of upstream's previous chart, and `make helm.package.release` stamps the release asset instead.
- When the fork moves to a new upstream release, compare `appVersion` in `deploy/charts/external-secrets/Chart.yaml` with the tags the fork has published. Upstream's file holds its previous release there, and an image tag left empty in the chart falls back to it (`templates/_helpers.tpl`). Once that version is one the fork released, an install from the chart directory that omits the tag runs that older image on the new CRDs instead of failing to pull. The release chart and the add-on pin the tag, so they are not affected; the comments on the three `tag` values in `values.yaml` are what has to stay true.
- golangci-lint only analyzes files whose build constraints are satisfied; `.golangci.yaml` sets `run.build-tags: [ncloud, ncloud_live]`, which covers every tag-gated file this fork owns (`pkg/register/ncloud.go` and the opt-in live tests). Adding a file behind a new build tag makes it invisible to lint, gofmt included, until that tag is listed there too.
- Files behind a build tag are invisible to `make test`, lint and gofmt until the tag is passed. Build them with `make test TEST_PROVIDER=all_providers,ncloud_live TEST_PKGS=./providers/v1/ncloud/...` (comma-separated, not space-separated, which `go test` reads as a package path). Without this an unused import in a `ncloud_live` file only surfaces in CI.
- Credentials a platform injects into the controller pod (the Pod Identity token file and exchange URL) are read from the environment once, in `NewProvider()`, and kept on `Provider` fields; tests set the fields instead of the environment, and admission (`ValidateStore`) never reads them, because the webhook pod's environment is not the controller's.
- Go files this fork adds start with NAVER Cloud's three-line header (`// External Secrets Operator for NAVER Cloud Platform`, `// Copyright (c) 2026-present NAVER Cloud Corp.`, `// Apache-2.0`), and so does every other source file it adds that the public tree ships, such as a script or a workflow, in that file's comment syntax and below any shebang line; upstream files, including the ones the fork modifies, keep upstream's ESO header, and a modified one carries `Modified from https://github.com/external-secrets/external-secrets by NAVER Cloud Corp.` in a comment of its own below that header, or at its top when it has none (Apache-2.0 section 4(b)); this holds for every hand-edited upstream file, Markdown and YAML included, while `go.mod`, `go.sum` and generated files (`zz_generated.deepcopy.go`, CRDs, snapshots, the API reference) carry none because tooling rewrites them. `.licenserc.yaml` has one rule per kind, so a new fork-owned Go path must be added to both of its lists (ignored by the first, checked by the second), or `make license.check` fails on it; the first rule covers only Go, so a fork-owned script goes in the second list alone.
