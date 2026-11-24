<!-- Modified from https://github.com/external-secrets/external-secrets by NAVER Cloud Corp. -->

# Security Policy

This policy covers what this repository adds to External Secrets Operator:
the `ncloud` provider, its CRD fields and documentation, and this fork's
build (the image and the release chart). Code shared with upstream (the
controllers, the webhook, the APIs and the other providers) follows the
[upstream security policy](https://github.com/external-secrets/external-secrets/blob/main/SECURITY.md).
If you cannot tell which side a problem is in, report it here and say so;
we will tell you whether it belongs upstream.

## Supported versions

Fixes go to the most recent release. There is no long-term support branch
and older tags are not patched: upgrade to the latest release first, then
report if the problem is still there. Upstream security fixes arrive by
moving to the upstream release that contains them.

## Reporting a vulnerability

Report privately through GitHub, not in a public issue:

**[Open a draft security advisory](https://github.com/NaverCloudPlatform/external-secrets/security/advisories/new)**,
or use *Security > Advisories > Report a vulnerability* on this repository.

Only the maintainers can see a report filed this way, and it stays private
until a fix is released.

Helpful in a report: the controller image (`kubectl -n external-secrets get
deploy external-secrets -o jsonpath='{.spec.template.spec.containers[*].image}'`),
whether it was installed with the release chart or the NKS add-on, and the
smallest store and `ExternalSecret` or `PushSecret` that show the problem.
Leave access keys, secret values, role NRNs and cluster identifiers out of
it.

You will get an acknowledgement that the report was received, and an update
when it is triaged. If a fix is needed, the advisory is where it is
coordinated and published.

## Already documented, not a finding

These are known properties of the design, described in the
[provider documentation](docs/provider/ncloud.md), and a report about them
will be closed as such:

- **A store reaches whatever its credential reaches.** Every namespace
  allowed to use a store reads, and with write permissions pushes to, every
  secret the store's key or role can reach. Secret Manager scopes access by
  Sub Account policy, not by Kubernetes namespace. See
  [Ownership marker](docs/provider/ncloud.md#ownership-marker) and
  [Required Permissions](docs/provider/ncloud.md#required-permissions).
- **The ownership marker is not a namespace boundary.** The
  `managed-by: external-secrets` memo line says that external-secrets
  created a secret, not which store or namespace did, so any `PushSecret`
  whose store may write a secret can update or delete it. See
  [Ownership marker](docs/provider/ncloud.md#ownership-marker).
- **`serverRole` and `podIdentity` share one identity across the
  cluster.** Both are accepted only in a `ClusterSecretStore`; one published
  without `conditions`, with an empty `namespaceSelector`, or with a regex
  such as `.*` is admitted with a warning, and a selector that matches
  every namespace in some other way is admitted without one. Either way it
  serves every namespace. Every pod on a node
  can also read that node's Server Role through the instance metadata
  endpoint, which is a property of the node role, not of this provider. See
  [Server Role](docs/provider/ncloud.md#server-role-serverrole) and
  [Pod Identity](docs/provider/ncloud.md#pod-identity-podidentity).
- **A store's author chooses its endpoint.** The `endpoint` field accepts
  any `https://` URL, so whoever may create a store decides where requests
  signed with its credential go. This is why the node's and the
  controller's identities are limited to `ClusterSecretStore`.

A way to get *past* one of these boundaries, such as reading a secret the
store's credential should not reach, making the controller send a key or a
signed request somewhere the store or the controller's configuration did
not name, or getting a key or a secret value out of the controller's logs,
events or metrics, is a finding, and we want to hear about it.
