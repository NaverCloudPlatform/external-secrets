## Ncloud Secret Manager

External Secrets Operator integrates with [Ncloud Secret Manager](https://www.ncloud.com/product/security/secretManager) (NAVER Cloud Platform).

The YAML examples on this page are files in `docs/snippets/`. Where the page
is read unrendered, as on GitHub, each `include` line names the file in that
directory that the rendered page shows in its place.

!!! warning "Run an image built from this repository"
    Upstream External Secrets Operator images do not include the Ncloud
    provider. An image built from this repository (`make docker.build`) is
    built with `PROVIDER=all_providers` by default, as upstream's are, so it
    registers every upstream provider and the Ncloud one. A build with
    `PROVIDER=ncloud` registers only Ncloud and upstream's always-built
    Kubernetes provider, and its admission webhook **rejects stores for
    AWS, Vault, or any other provider** rather than ignoring them. If you
    publish an image of your own, point the chart's `image`,
    `webhook.image` and `certController.image` values at it.

### Store Configuration

A store names the Secret Manager endpoint and where the access key pair that
signs requests comes from: a Kubernetes Secret referenced via `secretRef`, as
below, the node's Server Role, or the controller pod's Pod Identity (see
[Authentication](#authentication)).

```yaml
{% include 'ncloud-secret-store.yaml' %}
```

The endpoint is an `https://` base URL. Ncloud documents these endpoints, and
they are scoped by the KMS key isolation boundary of the secrets they serve,
not just by region:

| Region | Secrets protected by a GLOBAL key | Secrets protected by an ISOLATED key |
|---|---|---|
| KR | `https://secretmanager.apigw.ntruss.com` | `https://ocapi-kr.ncloud.com/secretmanager` |
| JPN | (not offered) | `https://ocapi-jp.ncloud.com/secretmanager` |

New secrets can only use ISOLATED keys: the
[API overview](https://api.ncloud-docs.com/docs/secretmanager-api-overview)
states that a new secret can no longer select a global key, so new setups
should use an `ocapi` endpoint. The `apigw` endpoint keeps serving secrets
created earlier with GLOBAL keys.

!!! warning "Endpoint and key boundary must match"
    Each endpoint serves one key boundary and enforces it on create: a
    `PushSecret` through a store on the wrong endpoint fails at create with
    nothing created, and the error names the boundary the request declared.
    Reads, updates, and deletes of existing GLOBAL-key secrets keep working
    through `apigw`. To manage both kinds of secrets, create one SecretStore
    per endpoint. If a value update of a secret the store can read is refused
    with 409, the error names the boundary of the secret's key; point the store
    at the endpoint for that boundary.

Any other `https://` host is accepted as well, for example a proxy in front
of an official endpoint. The store has no CA bundle field, so such a host must
present a certificate the controller's system trust store accepts. A mistyped
host is not caught at admission: one that answers 404 marks the store
`Ready=False`, and one that does not resolve or does not answer marks it
`Ready=True` with reason `ValidationUnknown` and a `Warning` event (see
[Store readiness](#store-readiness)). Redirects are not followed: a host that
answers with a 3xx fails every request with that status, and the store shows
`Ready=True` with reason `ValidationUnknown`.

!!! warning "Who may create a store"
    The admission webhook does not check that a store's author may read the
    Secret its `secretRef` names; the controller reads it. Permission to
    create a `SecretStore` in a namespace therefore amounts to permission to
    sign requests with every Ncloud key stored in a Secret there, and the
    store's `endpoint` chooses the host those requests are sent to. Grant
    `create` on `secretstores` only to those who may use every key stored in
    the namespace, or restrict `endpoint` with a policy engine, as the
    [threat model](../guides/threat-model.md) recommends for provider fields
    such as `url`.

Requests to the Secret Manager endpoint and to the Secure Token Service go
through Go's default transport, which honors `HTTPS_PROXY` and `NO_PROXY`
from the controller's environment; only the instance metadata address is
exempt (see [Server Role](#server-role-serverrole)). The Pod Identity
exchange honors the same settings, so an operator who needs it to bypass a
proxy sets `NO_PROXY` for its host.

Plain `http://` is rejected by the CRD schema, because every request carries
the access key ID and an HMAC signature. The host is lowercased and trailing
`/` characters are removed. A value that cannot serve as a base for request
paths is rejected at admission: whitespace, a query, a fragment, credentials
in the URL, `.` or `..` segments, percent-encoding, non-ASCII characters
(write an internationalized host in its `xn--` form), or a path character
that would be sent percent-encoded, such as `{`.

Ncloud offers Secret Manager in the KR and JPN regions only. A cluster
elsewhere uses one of those endpoints over the internet, and the endpoint's
region is where the secret data is stored.

#### Name resolution cache

The provider resolves a secret name to its ID by reading the full paginated
listing. Resolved mappings are cached per endpoint and signing identity, across
reconciles and stores: positive entries live 15 minutes, "not found" entries 5
minutes. The identity is the access key ID together with its secret key for
`secretRef`, the node for `serverRole`, the controller pod's token file and
exchange endpoint for `podIdentity`, and the role together with the identity
that switched to it for `role`. Consequences:

- A secret created outside external-secrets is noticed up to 5 minutes after
  something has already looked for that name and not found it. Reads and
  pushes both record that verdict, so a `PushSecret` that found a name missing
  delays a later `ExternalSecret` read of the same name as well.
- Two `SecretStore`s in different namespaces that share an access key pair
  share these verdicts.
- Only name to ID metadata is cached; secret values are always fetched fresh.

Every unresolved name costs up to a full listing: a sweep ends at the page
where it finds a live secret with the name. When the listing spans more than
one page, every `find`, and every lookup that concludes a name is absent,
reads it twice (the keys of one `PushSecret` share those reads). Each create
repeats the absence check under the name's lock, whatever the number of
pages. Prefer few `PushSecret` resources that create many names over many
that create one, and expect the first sync after a large batch of creates to
be slow.

### Authentication

Ncloud signs every request with HMAC-SHA256 over an access key pair. The
provider obtains the pair in one of three ways, and any of them can be
followed by a role switch. Exactly one of `auth.secretRef`, `auth.serverRole`
and `auth.podIdentity` must be set; the CRD enforces it, and the webhook and
the client check it again.

| Method | Requests are signed with | Stored in the cluster | Permissions belong to |
|---|---|---|---|
| `auth.secretRef` | a permanent key from a Kubernetes Secret | the key | the key |
| `auth.serverRole: {}` | the temporary key of the node's Server Role | nothing | the role |
| `auth.podIdentity: {}` | the temporary key of the role associated with the controller pod's ServiceAccount through Pod Identity | nothing | the role |
| any of them, plus `role:` | the temporary key of the switched role | as above | the target role (the key above needs only `switchRole` on it) |

#### Permanent access key (`secretRef`)

Store your Ncloud credentials in a Kubernetes Secret:

```yaml
{% include 'ncloud-credentials-secret.yaml' %}
```

`accessKeyIDSecretRef` and `secretKeySecretRef` reference the Kubernetes
Secret keys holding the pair. Both selectors require a nonempty `name` and
`key`. Unlike the endpoint, this is enforced by the admission webhook and
again when the provider builds its client, not by the CRD: a store written
with `accessKeyIDSecretRef: {}` is accepted by `kubectl apply` where the
webhook is absent or set to `failurePolicy: Ignore`, and fails when it is
first used. A `SecretStore` may only reference Secrets in its own namespace.

For a `ClusterSecretStore`, an omitted selector `namespace` is referent: the
credential is read from the namespace of each consuming `ExternalSecret` or
`PushSecret`. The store readiness check has no consuming namespace, so a
`ClusterSecretStore` with either credential namespace omitted makes no API
call and is reported `Ready=True` with reason `Valid` without its credentials
having been checked. Set an explicit namespace on both selectors when the
credentials live in a fixed namespace and store-level readiness should mean
something.

#### Server Role (`serverRole`)

```yaml
{% include 'ncloud-secret-store-server-role.yaml' %}
```

An `ExternalSecret` or `PushSecret` in a namespace listed in `conditions` uses
it with
`secretStoreRef: {kind: ClusterSecretStore, name: ncloud-cluster-store}`.

With `auth.serverRole: {}` the provider signs with the temporary key of the
Server Role attached to the node it runs on, read from the instance metadata
endpoint (`http://169.254.169.254/latest/meta-data/iam/security-credentials`).
Nothing is stored in the cluster. Only a `ClusterSecretStore` may use it; see
the warning below. The key is replaced five minutes before it expires, and a
request refused with 401, or with a 404 carrying the API Gateway's code `300`,
is retried once with a fresh key (see [Errors and Retries](#errors-and-retries)).
A replacement that fails is retried every 30 seconds while the old key is
still valid, and when a refresh returns the key just refused, further
refusals of it do not trigger another refresh for 30 seconds. The
metadata is read with a Metadata v2 session token, so a server whose Metadata
API setting is "v2 (token required)" works as well as one that also accepts v1.

On Ncloud Kubernetes Service the role is the node pool's **Node IAM Role**,
chosen when the node pool is created. Server Roles exist on VPC servers only.
Check that the endpoint answers from a pod on the controller's node before
switching a store over. The probe is pinned to that node, because a pod on
another node pool asks a different node's role:

```shell
NODE=$(kubectl -n external-secrets get pod -l app.kubernetes.io/name=external-secrets \
  -o jsonpath='{.items[0].spec.nodeName}')
kubectl -n external-secrets run metadata-probe --rm -it --restart=Never --image=curlimages/curl \
  --overrides="{\"spec\":{\"nodeName\":\"$NODE\"}}" \
  --command -- sh -c 'curl -sS -o /tmp/t -w "token request: %{http_code}\n" -X PUT \
  -H "X-NCP-METADATA-TOKEN-TTL-SECONDS: 60" http://169.254.169.254/latest/api/token; \
  curl -sS -i -H "X-NCP-METADATA-TOKEN: $(cat /tmp/t)" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials'
```

`token request: 200` means the node issues Metadata v2 tokens; otherwise the
provider reads without a token, which works only on a node that also accepts
v1. `HTTP/1.1 200` with the role ID means a role is attached and reachable,
`404` means the node has no role, and a connection error means the pod cannot
reach the address. The provider does not use `HTTP_PROXY` for this address.

!!! warning "Who can use the node's role"
    Every pod on the node can read the metadata endpoint, so every pod there
    can obtain the role's key: give the role only the permissions listed
    below, run the controller on a node pool of its own, and block
    `169.254.169.254` for other namespaces with a NetworkPolicy. Without
    that, the store restriction below adds little.

    `serverRole` is accepted only in a `ClusterSecretStore`: the webhook
    rejects it in a `SecretStore`, and the controller refuses to build a
    client for one that got past admission. The node's role is shared by
    every store, and a store's author chooses the host that requests signed
    with it are sent to (see "Who may create a store" under
    [Store Configuration](#store-configuration)), so at cluster scope that
    choice belongs to whoever may create a `ClusterSecretStore`. Publish the
    store with `conditions` listing the namespaces that may use it; a store
    without them, or with a condition that matches every namespace (an empty
    `namespaceSelector`, or a regex such as `.*` or `""`), is admitted with a
    warning. Teams that need a store of their own use `secretRef` with their
    own key, and giving the node's role only `switchRole`, with the Secret
    Manager permissions on per-team roles, narrows what a mistake exposes.

A store whose node has no role, or whose pod cannot reach the metadata
address, is reported `Ready=False` like a rejected key.

#### Pod Identity (`podIdentity`)

```yaml
{% include 'ncloud-secret-store-pod-identity.yaml' %}
```

With `auth.podIdentity: {}` the provider signs with the temporary key of the
role that Ncloud Kubernetes Service **Pod Identity** associates with the
controller pod's ServiceAccount. Nothing is stored in the cluster, and unlike
a Server Role the key is not reachable from ordinary pods on the node. Only a
`ClusterSecretStore` may use it; see the warning below.

Three things must be in place:

1. The **Pod Identity add-on** is installed in the cluster, and the
   controller pod carries the label `nks.ncloud.com/pod-identity: "true"`.
   When a pod with that label is created, the add-on injects a projected
   ServiceAccount token
   (`/var/run/secrets/nks.ncloud.com/pod-identity/token`, audience
   `<clusterUuid>.pod-identity.nks.ncloud.com`) and two environment
   variables, `NCLOUD_POD_IDENTITY_TOKEN_FILE` and
   `NCLOUD_POD_IDENTITY_API_ENDPOINT`. A pod created without the label, or
   before the add-on was installed, has neither. A controller pod that
   carried the label before the Pod Identity add-on was installed has to be
   restarted
   (`kubectl -n external-secrets rollout restart deploy/external-secrets`).
   Where the NKS add-on catalog offers the `external-secrets` add-on, an
   install from it carries the label already. The Helm chart sets none, so
   give it to the controller in the chart's values, as below; the upgrade
   that adds it replaces the pod.
    ```yaml
    podLabels:
      nks.ncloud.com/pod-identity: "true"
    ```
2. A **Pod Identity association** maps the controller's namespace and
   ServiceAccount to a Service Role. Installed as the README describes
   (release and namespace `external-secrets`), both are `external-secrets`;
   the ServiceAccount is `spec.template.spec.serviceAccountName` of the
   controller Deployment.
   Register the association in the Ncloud console (cluster detail, Pod
   Identity) or through its API.
3. The **Service Role** has Ncloud Kubernetes Service as a target service and
   carries the [permissions below](#required-permissions).

Only the controller needs the label: the webhook and cert-controller pods
make no Ncloud calls, and their labels are separate values
(`webhook.podLabels`, `certController.podLabels`). Each of the three
replaces `global.podLabels` instead of adding to it, so a release that sets
`global.podLabels` repeats those labels in `podLabels`.
On the command line pass the label with `--set-string`
(`--set-string 'podLabels.nks\.ncloud\.com/pod-identity=true'`): a label
value is a string, and `--set` would pass the boolean `true`, which
Kubernetes does not accept as one. A labeled pod gets a key only if its
ServiceAccount is associated, so associate the controller's ServiceAccount
alone. A controller pod without the label is not injected, and unless the
two variables reach it some other way it reports the missing-environment
error.

The association is checked on every exchange, and the controller exchanges
only when it has no key or its key is five minutes from expiry. A new
association therefore takes effect at the store's next check without a
restart. A changed or removed one does not: the controller keeps signing
with the key it holds until that key is replaced, expires or is refused,
and a refused exchange does not take the key away. Restart the controller
to apply a change, a removal in particular, at once. A controller pod
created before the add-on was installed also needs a restart.

The provider reads the token file right before each exchange, so the token the
kubelet rotates is always the one sent, posts it as a bearer token to the
exchange endpoint, and signs Secret Manager requests with the key it gets
back. The key is replaced five minutes before it expires, and a request
refused as described for a Server Role is retried once with a fresh key, with
the same holds. The exchange endpoint comes from the environment the add-on
injected, not from the store and not from a controller flag.

To see what the controller gets, run the exchange from a pod that uses the
controller's ServiceAccount and carries the label (the controller image has
no shell, and the add-on injects a token for the same ServiceAccount into
any labeled pod that uses it):

```shell
kubectl -n external-secrets run pod-identity-probe --rm -it --restart=Never \
  --image=curlimages/curl \
  --labels=nks.ncloud.com/pod-identity=true \
  --overrides='{"spec":{"serviceAccountName":"external-secrets"}}' \
  --command -- sh -c 'test -n "$NCLOUD_POD_IDENTITY_TOKEN_FILE" || { echo "not injected"; exit 1; }; \
  T=$(cat "$NCLOUD_POD_IDENTITY_TOKEN_FILE") || exit 1; \
  curl -sS -o /dev/null -w "%{http_code}\n" -X POST \
  -H "Authorization: Bearer $T" "$NCLOUD_POD_IDENTITY_API_ENDPOINT"'
```

| Answer | Meaning |
|---|---|
| `200` | the add-on and the association are in place; the store works if the role has the [permissions below](#required-permissions) |
| `400` | the token's audience is not this cluster's (InvalidAudience): the add-on is misconfigured |
| `401` | the token was refused (InvalidToken): expired, from another cluster, or not bound to a running pod |
| `403` | no association for this namespace and ServiceAccount, or the role does not target Ncloud Kubernetes Service (NoAssociation) |
| `404` | no exchange API at this address: the injected endpoint is wrong |
| `503` | the exchange service is temporarily unavailable (UpstreamError); try again |
| `not injected` | the add-on is not installed or was not ready when the pod was created, or the pod lacks the label `nks.ncloud.com/pod-identity: "true"` |

The store reports the same answers: `400`, `401`, `403`, `404` and any other
refusal, a missing or empty token file, a controller without the injected
environment, and an injected endpoint that is not `https` all make the store
`Ready=False`, with the cause in the controller log (see
[Store readiness](#store-readiness)); any `5xx`, a `408` or
`429`, or a timeout leaves it `Ready=True` with reason `ValidationUnknown`
until the next check. The missing-environment and non-`https` endpoint
cases fail when the client is built, so their condition message is
`unable to create client` rather than `unable to validate store`, with the
same reason.

!!! warning "Who can use the controller's Pod Identity"
    `podIdentity` is accepted only in a `ClusterSecretStore`, for the reason
    given for `serverRole` above: a store's author chooses the host that
    requests signed with the controller's key are sent to, so at cluster
    scope that choice belongs to whoever may create a `ClusterSecretStore`.
    Publish one with `conditions` listing the namespaces that may use it; a
    store without them, or with a condition that matches every namespace, is
    admitted with a warning. What differs from a Server Role is the
    exposure: the token lives in the controller pod's projected volume and
    the exchange accepts it only while it is bound to a running pod, so
    unprivileged pods on the node cannot obtain the key. Whoever can create
    pods in the controller's namespace (a pod may name any ServiceAccount
    there), request tokens for the controller's ServiceAccount
    (`serviceaccounts/token`), modify the controller Deployment or add
    ephemeral containers to its pod, or run privileged or `hostPath` pods on
    its node, can. That makes the namespace's RBAC and node isolation the
    boundary, rather than a NetworkPolicy.

#### Switching to a role (`role`)

```yaml
{% include 'ncloud-secret-store-switch-role.yaml' %}
```

`role` names a role NRN. After obtaining its own pair, the provider calls the
Secure Token Service (`POST /api/v1/switch-role`) and signs every Secret
Manager request with the role's temporary key instead. The switched key has
the service's default lifetime of one hour and is replaced five minutes before
it expires. Stores that share a key and a role share one switched key; a pair
no store has used for 15 minutes is dropped.

The Secure Token Service endpoint is a controller flag,
`--ncloud-sts-endpoint` (default `https://sts.apigw.ntruss.com`, an `https://`
base URL checked by the same rules as a store's `endpoint`; a value that
breaks them stops the controller at startup with a flag error), not a store
field, so that a store cannot choose the host that receives switch requests
signed with the node's key. Set it through the chart's
`extraArgs` when a deployment must use another host, such as a proxy:

```yaml
extraArgs:
  ncloud-sts-endpoint: https://sts-proxy.example
```

A role switch that the Secure Token Service refuses (any 4xx other than 408
or 429) is reported as a rejected role switch, and the store is reported
`Ready=False`.

#### Store readiness

Outside the referent case, the readiness check lists the first page of
secrets and reports:

- a rejected credential (401 or 403), a credential source that cannot produce
  a key (no Server Role, a metadata endpoint that cannot be reached or that
  refuses the request, no Pod Identity token in the pod, a Pod Identity
  exchange that answers with any 4xx other than 408 or 429, a refused role
  switch, a metadata, exchange or Secure Token Service answer that is not a
  complete key pair), or a listing endpoint that answers 404 (the endpoint is
  wrong for this account's region, the account has no Secret Manager, or the
  access key was not accepted; see [Errors and Retries](#errors-and-retries)):
  `Ready=False`, reason `InvalidProviderConfig`. Nothing will work until the
  spec or the account changes.
- any other failure, such as a timeout or a 5xx: `Ready=True` with reason
  `ValidationUnknown` and a `Warning` event, because the store may be fine.
  The store is checked again on the next requeue.

The condition's message and the `Warning` event carry fixed text from the
store controller, such as `unable to validate store`, not the provider's
error, which may carry secret material. For `Ready=False` the controller logs
the provider's error, which names the cause, next to that text
(`kubectl logs` on the controller). For `ValidationUnknown` the store
controller logs only `could not determine validation status` and drops the
provider's error: when the same failure recurs on a read or a write through
the store, that reconcile's `Reconciler error` names it, and otherwise the
cause is recorded nowhere. A 401 means the key is wrong, or that the controller
node's clock is more than five minutes off: the
[API Gateway](https://api.ncloud-docs.com/docs/common-ncpapi) refuses a
signature whose timestamp is outside that window with the same answer.

### Required Permissions

The access key needs the Secret Manager API operations below. Ncloud's
managed Sub Account policies are `NCP_VPC_SECRET_MANAGER_MANAGER` (all Secret
Manager features) and `NCP_VPC_SECRET_MANAGER_VIEWER` (view functions only);
a store that only reads can use the latter, while push and delete need the
former or a custom policy with the corresponding change actions.

| What you do | Operations the provider calls |
|---|---|
| Validate the store | list secrets `GET /api/v1/secrets` (first page). A key without this permission makes the store `Ready=False`, and under the controller's default `--enable-flood-gate` every `ExternalSecret` that references the store is then refused, including reads by ID that the key could serve |
| Read a secret (`data`, `dataFrom.extract`) | list secrets (to resolve a name; not for an ID or a cached name), get secret value `GET /api/v1/secrets/{id}/values`, and get secret detail `GET /api/v1/secrets/{id}` when a value read fails, to confirm a pending deletion |
| Read with `metadataPolicy: Fetch` | list secrets, get secret detail |
| `dataFrom.find` | list secrets (every page), get secret value for each selected secret, get secret detail when a value read fails |
| `updatePolicy: IfNotExists` check | list secrets, get secret detail, and get secret value when a `property` is set |
| Push to an existing secret | list secrets, get secret detail (ownership), get secret value, update stage value `PUT /api/v1/secrets/{id}/values/active` |
| Push that creates a secret | list secrets, list protection keys `GET /api/v1/keys` (to find the default key's KMS boundary), create secret `POST /api/v1/secrets` |
| Delete a `property` | list secrets, get secret detail, get secret value, update stage value |
| Delete a whole secret | list secrets, get secret detail, request deletion `POST /api/v1/secrets/{id}/request-deletion` |
| Delete with `forceDeleteWithoutRecovery` | the above, plus destroy secret `DELETE /api/v1/secrets/{id}` |
| Switch to a `role` | `switchRole` on the target role, for the key the store signs with; everything above belongs to the target role |

If protection keys cannot be listed, the create omits `kmsBoundaryType`, which
an account whose default key is ISOLATED rejects with a 400; the controller
logs the failed lookup.

### Reading Secrets

A `remoteRef.key` is either a secret name or a secret ID. Names are what the
Create Secret API accepts: **3 to 15 characters, starting with a letter, made
of letters, digits, `-` and `_`**. IDs are 64 lowercase hex characters. A key
that is neither cannot exist remotely and is refused before any API call: the
`ExternalSecret` reports a sync error, the controller log names the rule,
and the target Secret is left as it is, because a mistyped key is not a
missing secret and `deletionPolicy: Delete` must not act on it. The same
rule applies to every remote key on this page; deleting a key that breaks it
does nothing and succeeds, since no secret can exist under it.

```yaml
{% include 'ncloud-external-secret.yaml' %}
```

#### JSON values and properties

Secret values are flat JSON objects whose values are strings (the API
refuses nested objects, numbers and arrays). Use `property` to extract one
key. Given a secret `db-cred` holding:

```json
{
  "username": "admin",
  "password": "s3cr3t"
}
```

```yaml
{% include 'ncloud-external-secret-json.yaml' %}
```

A `property` is tried as a literal key first, so flat keys such as `tls.crt`
work; only if no literal key matches is a dotted name read as a nested path.
For secret values the literal step is the one that applies, since values
cannot nest; nested paths matter for `metadataPolicy: Fetch` below. A property
whose value is JSON `null` is reported as not found rather than synced as an
empty string.

Use `dataFrom.extract` to sync every key of a JSON secret at once:

```yaml
{% include 'ncloud-external-secret-json-extract.yaml' %}
```

#### Versions (stages)

Ncloud versions a secret as a fixed three-stage chain instead of numbered
versions: during rotation a new value enters `pending`, is promoted to
`active`, and the prior value moves to `previous`. `remoteRef.version` selects
the stage:

```yaml
  data:
    - secretKey: next-password
      remoteRef:
        key: app-secret
        version: pending   # one of: previous | active | pending
```

- Omitting `version` reads `active`.
- Stage names are matched case-insensitively; any other value is rejected.
- A stage with no value (for example `pending` outside a rotation) fails with
  a "secret data is empty" error rather than falling back to another stage.
  That is a sync error, not a missing secret, so `deletionPolicy: Delete`
  does not act on it.
- A `PushSecret` writes the `active` stage in place, and so does the deletion
  of a `property`: neither moves the value it replaces to `previous`, so
  `version: previous` does not return it.

#### Metadata (`metadataPolicy: Fetch`)

Set `metadataPolicy: Fetch` to sync a secret's metadata (Get Secret Detail)
instead of its value. The decrypted value is never part of the document.

```yaml
  data:
    - secretKey: secret-status
      remoteRef:
        key: app-secret
        metadataPolicy: Fetch
        property: secretStatus        # optional: pick one metadata field
```

- Without `property`, the whole document is returned as JSON (`secretId`,
  `secretName`, `secretStatus`, `secretType`, `memo`, `region`, timestamps,
  rotation fields, `trigger`, `protectionKey`).
- `property` selects one field, including nested ones such as
  `protectionKey.type`.
- `version` is ignored; metadata is not staged.
- A secret whose deletion is pending (`REVOKE`) is returned with
  `secretStatus: REVOKE` instead of being reported absent, so this recipe
  observes a pending deletion. A `DESTROYED` secret is reported absent, though
  a mapping cached by an earlier value read can keep answering with its
  document for up to 15 minutes; do not rely on that.

#### Secrets in a deletion or paused state

A secret whose deletion was requested (`REVOKE`) or that is destroyed is
treated as absent by every value read: a single-secret read reports the
missing-secret error that `deletionPolicy` acts on, and `find` skips it. When
a value read is refused the way these states refuse one (a `409` or a `400`),
the provider confirms the state with a detail read before reporting absence.
A `404` that carries Ncloud's resource-not-found code is absence without that
detail read; a read by name first looks the name up in the listing once more
and reads the secret it finds there. A row the listing itself reports as
`DESTROYED`, and in `find` one it reports as `REVOKE`, is taken as absent on
the listing's word.
A paused (`DISABLE`) secret is **not** reported absent: its reads fail with
an error, because the value still exists.

!!! note "Two secrets with one name"
    A secret whose deletion was requested keeps its row in the listing, as
    `REVOKE`, for the grace period. A name held by a live secret always
    resolves to that secret, whatever order the listing returns rows in. Should
    several live secrets hold one name, the first one the listing returns
    wins, the same way for a read, a `find` and a push. That can change if
    the other is deleted, and the second cannot be addressed by name, so
    delete one of them.

### Finding Secrets

Use `dataFrom` with `find` to retrieve multiple secrets. A `path` prefix and
a `name.regexp` are supported and combine (a secret must match both). A
`find` with neither selects every secret of the account, which the AWS and
GCP providers refuse but the Azure provider also allows; each selected secret
costs one value read. Each matching Ncloud secret becomes one key, named
after the secret, whose value is that secret's whole JSON document; use
`rewrite` to rename keys.

```yaml
{% include 'ncloud-external-secret-find.yaml' %}
```

`find` fails closed, because the operator rewrites the target Secret from
whatever map `find` returns and a partial result would delete keys:

- Tags are not supported by the Ncloud API; a non-empty `find.tags` is
  rejected.
- `REVOKE` and `DESTROYED` secrets are skipped, and so is a secret deleted
  between the listing and its value read.
- `Forbidden` and every other read failure abort the whole `find`, keeping
  the last synced data in place.
- If the listing changes while it is being read, its rows do not add up to
  the total it declares, or it returns one secret twice, `find` reads it
  again. It reads the listing at most three times in all, the confirming
  read of a listing longer than one page included, and then fails with
  `secret listing changed while it was being read; refusing to report a
  possibly incomplete result`. Nothing is written on the Kubernetes side,
  and the next reconcile retries. If it recurs on every sync, something is
  creating or deleting secrets in the account continuously, or the listing
  keeps failing one of those checks.

!!! warning
    A single **disabled** (`DISABLE`) secret, or one in a status this
    provider does not recognize, that matches your selector fails the entire
    `find`, including the secrets that are readable. A disabled secret still
    holds a value, so skipping it would delete its key from the target.
    Re-enable the secret, delete it, or narrow `path`/`name.regexp` so it no
    longer matches.

### Pushing Secrets

`PushSecret` writes a Kubernetes Secret to Ncloud Secret Manager. The remote
key is the Ncloud secret name (see [Reading Secrets](#reading-secrets) for the
name rule) or an existing secret's ID, and the value is written to the
**active** stage.

```yaml
{% include 'ncloud-push-secret.yaml' %}
```

- A missing secret is created with `BASIC` type, rotation off, the default
  protection key, and a memo holding the ownership marker (see
  [Deletion and Ownership](#deletion-and-ownership)). A remote key that is an
  ID never creates: an ID that does not exist fails the push.
- The create declares `kmsBoundaryType`, discovered from the account's default
  protection key rather than configured on the store (see
  [Required Permissions](#required-permissions)).
- Every value written is a nonempty JSON object of strings:
    - With `match.secretKey` and no `property`, the selected value is wrapped
      under its local key: selecting `password` writes `{"password":"..."}`.
      This **replaces** the remote value. Two `data` entries cannot share
      one `remoteKey` without `property`: the controller refuses the
      `PushSecret` with `duplicate remote key`.
    - Without `match.secretKey`, the whole Kubernetes Secret `Data` map is
      written as one object. Empty `Data` is rejected.
    - `property` merges the selected value under that one top-level field and
      preserves the others; the existing value must be a JSON object or empty.
      `property` requires `match.secretKey`: combining it with the whole
      `Data` map would nest an object, which Ncloud refuses, so it is
      rejected locally. Use `property` when several entries write to one
      remote secret.
    - Invalid UTF-8 in a selected key, property, data key, or data value is
      rejected.
- On the write side (`PushSecret`, `DeleteSecret`, the `IfNotExists` check),
  `property` is always one literal top-level field name: `property: a.b`
  writes a field named `a.b`. Reading `property: a.b` prefers that literal
  field too, but avoid dots in pushed property names.
- `spec.dataTo` without `remoteKey` makes every Kubernetes data key its own
  remote secret name, so keys such as `tls.crt` need a `rewrite` to satisfy
  the name rule. With `dataTo[].remoteKey` the Secret is written as one object
  under that single name (every key, or the keys that survive
  `dataTo[].match.regexp`), and the keys inside are unrestricted, which
  usually suits Ncloud better.
- `updatePolicy: IfNotExists` checks the exact top-level `property` when one
  is set; another property on the same secret does not prevent the write. An
  unreadable value, including `Forbidden`, is an error, not absence. A
  `REVOKE` secret counts as absent, so the push is attempted and fails loudly
  because the name is still occupied.
- A push that would not change the active value is skipped. The comparison is
  byte-for-byte, so adopting a console-created secret whose JSON differs only
  in key order or whitespace costs one rewrite.
- `metadata` is not supported and is rejected on both `spec.data[]` and
  `spec.dataTo[]`.
- A name held by a `REVOKE` or `DISABLE` secret cannot be written to; the
  error says which, and how to free or resume it. The ownership check runs
  first, so a `REVOKE` or `DISABLE` secret, or one addressed by ID, that
  lacks the [ownership marker](#ownership-marker) fails with the ownership
  error instead.

A second mutation of the same secret within one controller process fails with
a conflict error and is retried on the next reconcile, and a create rechecks
absence under that lock. A name that another writer took after this
reconcile's listing found it absent fails the push with an error saying so
rather than updating that writer's secret: the `IfNotExists` check answered
from the same listing, so updating would overwrite a secret the policy
promises to leave alone. The next reconcile lists the secret, so
`IfNotExists` skips it and `Replace` updates it. An update does not check
the value it replaces, so several controller replicas or other writers
targeting the same remote secret must be serialized operationally.

#### Rotation Targets

Ncloud fixes a secret's `rotationTargets` when it is created, with automatic
rotation on or off, and every later value must contain each of them: a value
that omits one is rejected with a 400.

- The provider derives the targets from the managed top-level fields of the
  push that creates the secret: the selected local key, every key of the
  whole `Data` map, or the explicit `property`.
- With several `property` entries for one remote key, the entry listed first
  in `spec.data` creates the secret and its property becomes the permanent
  target, so list the longest-lived property first.
- **A field that was a rotation target can never be removed from the value.**
  A push or a property deletion that would drop one is refused locally,
  naming the constraint, and the remote secret is left untouched. Removing
  such an entry from a `PushSecret` leaves it in error on every reconcile
  until the entry is restored or the remote secret is recreated.

To drop a rotation-target field, in safest-first order:

1. Restore the missing key in the value so every persisted target is present.
2. Migrate consumers and the `PushSecret` to a new remote key, whose create
   establishes the desired targets.
3. As a last resort, back up the value, quiesce every writer, delete the
   secret fully (the name stays held for the grace period unless
   `forceDeleteWithoutRecovery` is set), and let the next push recreate it.

### Deletion and Ownership

#### Ownership marker

Every secret this provider creates carries the line
`managed-by: external-secrets` in its memo (description). Mutating an existing
secret requires that marker:

- A push (value update or property merge) to a secret without the marker
  fails with an ownership error.
- A deletion of a secret without the marker, whole or by `property`, is
  skipped, logged at the default verbosity, and reported as success, so a
  `deletionPolicy: Delete` cleanup pointing at an external secret does not
  leave the `PushSecret` stuck in `Terminating`. If the memo cannot be read at
  all (for example `Forbidden`), the deletion fails instead.

To adopt an existing secret, put the marker on a line of its own in its memo
(console or the Update Secret Memo API); surrounding whitespace on that line
is ignored, but a line that merely contains the phrase does not count.
Removing the marker makes the secret unmanaged again. Cancel a pending
deletion before adopting a `REVOKE` secret.

The marker says that external-secrets created a secret, not which store or
namespace did: it is the same for every store, as the AWS provider's tag is.
Any `PushSecret` using a store whose key may write a secret can update or
delete it, whichever namespace pushed it, by naming it or its ID. Reads are
no narrower: `conditions` decide which namespaces may use a store, not which
remote secrets they reach through it, and a `dataFrom.find` in any of them
returns every secret the store's key can read. Namespaces that must not touch
each other's secrets need keys or roles whose permissions do not reach each
other's secrets, not one `ClusterSecretStore` shared through `conditions`.

#### Deleting a property

With a `property`, `DeleteSecret` removes that exact top-level field and
preserves every sibling. If it was the last field, the whole secret is deleted.
A missing field or secret succeeds silently. Removing a rotation target while
siblings remain is refused (see [Rotation Targets](#rotation-targets)). When a
`PushSecret` with `deletionPolicy: Delete` is removed, the controller deletes
its properties in no particular order, so the cleanup of a multi-property secret
can be refused and retried until the rotation target is the last one left, at
which point the whole secret is deleted.

A paused (`DISABLE`) secret refuses property deletion, because its value
cannot be read to preserve the siblings; resume it with Enable Secret first.
Deleting the whole secret does succeed from `DISABLE`. If the secret is
already `REVOKE` or `DESTROYED`, a property deletion reports success and never
escalates into destroying the secret.

#### Deletion lifecycle

A full delete requests deletion: the secret moves to `REVOKE` and Ncloud
destroys it automatically after a 7-day grace period. The secret's detail
reports the planned time as `expectedDestroyDate`, which a
`metadataPolicy: Fetch` read can return. During the grace period:

- the deletion can be canceled from the console or API (Cancel Secret
  Deletion parks the secret in `DISABLE`; Enable Secret brings it back);
- the secret keeps its name, and the provider refuses to recreate the same
  remote key until it is destroyed (a `PushSecret` for that key fails, and
  the controller log names the state and what frees the name).

Set `forceDeleteWithoutRecovery: true` on the store to skip the grace period
and destroy the secret immediately and irreversibly, like the AWS provider's
option of the same name. If the destroy call fails after the deletion request,
a later whole-secret delete finds `REVOKE` and finishes the job.

A `ROTATING` secret cannot be deleted and returns an error.

A delete by name that finds, at any step, that the secret it resolved is
already destroyed resolves the name once more and acts on a secret that holds
the name again, under the same ownership rule; if none does, or that one is
gone too, the delete is reported as done.

!!! warning "deletionPolicy: Delete and a missing source Secret"
    A `PushSecret` with `deletionPolicy: Delete` whose source Kubernetes
    Secret is not found deletes every remote secret it tracks (upstream
    behavior since v2.3.0). With the default deletion that is recoverable
    during the grace period (cancel the deletion requests); with
    `forceDeleteWithoutRecovery: true` a transient absence of the source,
    such as a GitOps prune-and-recreate, destroys them permanently. Prefer
    the default `deletionPolicy: None` unless that cleanup is intended.

### Errors and Retries

Returned errors carry the mapped category, the HTTP status, and, when the
service supplies one, the numeric Ncloud error code. Server-provided messages,
details, and response bodies are left out because they can contain
credentials or secret material.

The conditions and events of an `ExternalSecret`, a `PushSecret` or a store
do not carry these errors: they hold fixed text such as
`could not get secret data from provider`, because a provider error may
carry secret material. The controller logs the error itself, as the
`Reconciler error` of the object's reconcile, and the messages this page
quotes are what those log lines show. The exception is a store whose
validation ends in `ValidationUnknown`, whose cause the store controller
does not log (see [Store readiness](#store-readiness)).

!!! note "Secret listing unavailable (404)"
    A `404` from the secret **listing** endpoint is reported as
    `secret listing is unavailable ...`, never as a missing secret: a page
    past the last one answers with an empty list, not a 404. It
    typically means the Ncloud Secretstore (the product's term for the
    per-account secret collection, not the Kubernetes resource) is not
    provisioned for that account and region, or the endpoint is wrong. The
    error code in the controller log helps tell these apart: `501001` is
    Secret Manager's answer for a Secretstore that is not provisioned, and
    `300` is the API Gateway's, for a path it does not serve or a key it
    does not accept, such as an access key ID that Ncloud does not know, a
    temporary key past its expiry, or one whose Server Role was detached from
    the server. A temporary key refused this way is refreshed and the request
    re-sent once, so its 404 is reported only when that did not help (see the
    end of this section). A 404 on a single secret that does not carry Ncloud's
    resource-not-found code, such as one from a gateway or proxy, is also an
    error rather than absence, reported as
    `received 404 without a resource-not-found code ...`. A key that is not
    accepted can be answered this way too, so, unless the refused key was a
    temporary one whose refresh and re-send succeed, a read by ID fails this
    way without any listing, and a referent `ClusterSecretStore`, whose
    readiness check makes no call, stays `Ready=True` meanwhile. Treating
    either as "not found" would make `deletionPolicy: Delete` remove Kubernetes
    Secrets and `DeleteSecret` report success without deleting.

`GET` requests retry transient failures (rate limiting, any 5xx, a gateway
timeout, temporary network errors) up to three times with backoff. A `429`
from Secret Manager whose error code says the account's API quota is used up
is not transient and fails at once; a `429` from the Secure Token Service,
the Pod Identity exchange or the metadata address is always read as rate
limiting. Each `GET`,
attempts included, is bounded to 45 seconds; the bound is per request, so a
paginated listing spends it once per page. No single in-place wait exceeds 5
seconds: a `429` with a `Retry-After` of at most that is waited out when it
fits in what remains of the budget, and a longer one fails the request at
once so that the controller's own backoff carries the delay and one throttled
account does not hold the reconciles of every other store. A listing outside
the provider's bounds fails the request instead of being used: a page with
more than 1,000 rows, a sweep that reads more than 100,000 rows or runs
longer than 3 minutes, or a row whose secret ID is not 64 lowercase hex characters.
A sweep that the listing changed under, whose rows do not add up to its
declared total, or that returns one secret twice is read again; the listing
is read at most three times in all, a confirming read included, before the
request fails with `secret listing changed while it was being read; ...`.
This is not limited to `find`: a single-secret read, a push, the
`IfNotExists` check and a delete fail with the same error when the lookup of
the name would conclude that it is absent, or held only by a secret whose
deletion was requested. The error is then wrapped in `failed to resolve
secret name "<name>": ...`, behind the operation's own prefix for a push, a
delete and the `IfNotExists` check. A lookup that finds a live secret with
the name succeeds without this check.
Authorization, not-found, decoding and cancellation failures fail at once
(the exception, a refusal of a temporary key, is described at the end of this
section), and so do the credential-configuration failures (no Server Role or an
unreachable metadata address, a metadata address that refuses the request or
answers with a document that does not report success, a refused role switch
or Pod Identity exchange, a missing Pod Identity token, a credential response
that cannot be decoded, an incomplete temporary key), even when a network
error is the cause. A Secure Token Service or Pod Identity exchange that
cannot be reached for a moment is not one of them and is retried like any
other network error, except when the exchange is the refresh that follows a
refused temporary key: the request then fails at once, with both errors, as
described there.
An authentication failure (401) fails at once too, except that any request,
read or mutation, is re-sent once with a refreshed key when it was signed
with a temporary one. A 404 carrying the API Gateway's code `300` counts as
the same refusal for a temporary key.
The re-send happens only when the refreshed key differs. If the refresh itself
fails, the request fails and that failure is reported next to the 404, because
it is the cause an operator can act on; if the refreshed key is the same, the
404 is reported as described above. Mutating requests are not retried otherwise;
controller reconciliation supplies the higher-level retry.

### Monitoring

Every Secret Manager request increments the controller's
`externalsecret_provider_api_calls_count` counter with
`provider="Ncloud/SecretManager"`, a `call` label naming the operation, and
a `status` label of `success` or `error`:

| `call` | Request |
|---|---|
| `ListSecrets` | one page of the secret listing (name resolution, `find`, store validation) |
| `GetSecretValue` | get secret value |
| `GetSecretDetail` | get secret detail (metadata, ownership, deletion state) |
| `ListProtectionKeys` | list protection keys, before a create |
| `CreateSecret` | create secret |
| `UpdateSecretStageValue` | update stage value (push, property delete) |
| `RequestSecretDeletion` | request deletion |
| `DestroySecret` | destroy secret (`forceDeleteWithoutRecovery`) |

A `GET` is counted once, after its retries. `status` is the outcome of the
call, not how the provider read it: a value read that fails because the
secret is pending deletion counts as `error`, even though the provider then
reports the secret as absent. Requests for credentials (the instance
metadata endpoint, the Secure Token Service and the Pod Identity exchange)
are not counted themselves, but a credential failure counts as an `error` of
the Secret Manager call that needed the key, although that call was never
sent; the controller log says which step failed.
The controller's other metrics, such as `externalsecret_sync_calls_error`,
are listed in the [metrics reference](../api/metrics.md).

### Limitations

- Secret tags are not supported by the Ncloud API, so tag-based `find` and
  pushing tags are unavailable.
- A value is a JSON object of **1 to 100** key-value pairs, at most
  **10,000 bytes**, as the
  [Update Secret Stage Value](https://api.ncloud-docs.com/docs/secretmanager-update-secret-stage-value)
  reference states. The provider does not check either limit, so an
  oversized push, typically a whole Kubernetes Secret `Data` map, is
  rejected by the server.
- Rotation settings and protection keys are not managed by `PushSecret`;
  configure them in the Ncloud console or API. The memo is written once, at
  create, to carry the ownership marker; `PushSecret` never rewrites the memo
  of an existing secret.

Contributors: the opt-in live tests against a real account are described in
`providers/v1/ncloud/README.md`.
