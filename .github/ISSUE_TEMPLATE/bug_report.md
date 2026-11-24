---
name: Bug report
about: A problem in the ncloud provider or in this fork's build
title: ''
labels: kind/bug
assignees: ''

---

<!-- Modified from https://github.com/external-secrets/external-secrets by NAVER Cloud Corp. -->

Problems in other providers, or in controller and API code shared with
upstream, belong in the upstream project:
https://github.com/external-secrets/external-secrets/issues

**Describe the bug**
A clear and concise description of what the bug is.

**To reproduce**
1. The `SecretStore` or `ClusterSecretStore`, `ExternalSecret` or
   `PushSecret` manifests involved (redact credentials and secret values)
2. The image tag of this fork and the Kubernetes version
3. The Secret Manager endpoint and the authentication method
   (`secretRef`, `serverRole` or `podIdentity`, with or without `role`)

**Expected behavior**
A clear and concise description of what you expected to happen.

**Logs and events**
Controller logs and `kubectl describe` events for the resources above.
Never paste access keys, secret keys or secret values.

**Additional context**
Add any other context about the problem here.
