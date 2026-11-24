<!-- Modified from https://github.com/external-secrets/external-secrets by NAVER Cloud Corp. -->

# Contributing

This fork accepts changes to the `ncloud` provider, its documentation, and
the build and release tooling of the fork. Changes to code shared with
upstream External Secrets Operator (other providers, the controllers, the
APIs) belong in the
[upstream repository](https://github.com/external-secrets/external-secrets);
this fork picks them up when it moves to a newer upstream release.

## Before you open a pull request

- Build and test with the fork defaults: `make build` and `make test`.
  The opt-in live tests against a real account need the `ncloud_live` tag,
  `RUN_NCLOUD_E2E=true` and real credentials, for example
  `make test TEST_PROVIDER=all_providers,ncloud_live TEST_PKGS=./providers/v1/ncloud/...`;
  see [providers/v1/ncloud/README.md](providers/v1/ncloud/README.md).
- Run `make reviewable` and commit everything it changes. The generated
  CRDs, chart schema, chart documentation and snapshots are part of the
  tree.
- Keep the diff focused on the fork's scope. Upstream files are changed
  only when the fork needs it, so that upstream rebases stay small.
- Use the upstream commit title convention: `feat(scope): ...`,
  `fix(scope): ...`, `docs(scope): ...`, `chore(scope): ...`.
- Never put access keys, secret keys or secret values in code, tests,
  fixtures, issues or pull requests.

The upstream [developer guide](docs/contributing/devguide.md) describes the
build environment. `PROVIDER` is upstream's variable, with upstream's
default `all_providers`; the fork adds `TEST_PROVIDER`, `TEST_PKGS` and
`TEST_ARGS` for `make test`, and `RELEASE` and `IMAGE_TAG` for
`make helm.package.release`.
