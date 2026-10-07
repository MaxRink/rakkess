# rakkess
[![Build Status](https://github.com/corneliusweig/rakkess/actions/workflows/ci.yml/badge.svg)](https://github.com/corneliusweig/rakkess/actions/workflows/ci.yml)
[![Code Coverage](https://codecov.io/gh/corneliusweig/rakkess/branch/master/graph/badge.svg)](https://codecov.io/gh/corneliusweig/rakkess)
[![Go Report Card](https://goreportcard.com/badge/corneliusweig/rakkess)](https://goreportcard.com/report/corneliusweig/rakkess)
[![LICENSE](https://img.shields.io/github/license/corneliusweig/rakkess.svg)](https://github.com/corneliusweig/rakkess/blob/master/LICENSE)
[![Releases](https://img.shields.io/github/release-pre/corneliusweig/rakkess.svg)](https://github.com/corneliusweig/rakkess/releases)

Review Access - kubectl plugin to show an access matrix for server resources

Current Kubernetes client libraries no longer include the built-in GCP and
Azure authentication providers. Configure kubectl with an exec credential
plugin for those providers; OIDC authentication remains supported.

## Intro
Have you ever wondered what access rights you have on a provided kubernetes cluster?
For single resources you can use `kubectl auth can-i list deployments`, but maybe you are looking for a complete overview?
This is what `rakkess` is for.
It lists access rights for the current user and all server resources, similar to `kubectl auth can-i --list`.

It is also useful to find out who may interact with some server resource.
Check out the sub-command `rakkess resource` [below](#show-subjects-with-access-to-a-given-resource1).

## Demo
![rakkess demo](doc/demo-user-smaller.png "rakkess --namespace default")

## Examples
#### Show access for all resources
- ... at cluster scope
  ```bash
  rakkess
  ```

- ... in some namespace
  ```bash
  rakkess --namespace default
  ```

- ... with verbs
  ```bash
  rakkess --verbs get,delete,watch,patch
  ```

- ... for another user
  ```bash
  rakkess --as other-user
  ```

- ... for another service-account
  ```bash
  rakkess --sa kube-system:namespace-controller
  ```

- ... and combine with common `kubectl` parameters
  ```bash
  KUBECONFIG=otherconfig rakkess --context other-context
  ```
  
#### Show subjects with access to a given resource<sup>[1](#credit-kubectl-who-can)</sup>
![rakkess demo](doc/demo-resource-smaller.png "rakkess resource configmaps --namespace default")
- ...globally in all namespaces (only considers `ClusterRoleBindings`)
  ```bash
  rakkess resource configmaps
  ```
  
- ...in a given namespace (considers `RoleBindings` and `ClusterRoleBindings`)
  ```bash
  rakkess resource configmaps -n default
  ```

- ...with shorthand notation
  ```bash
  rakkess r cm   # same as rakkess resource configmaps
  ```

- .. with custom verbs
  ```bash
  rakkess r cm --verbs get,delete,watch,patch
  ```
  
##### Name-restricted roles
Some roles only apply to resources with a specific name.
To review such configurations, provide the resource name as additional argument.
For example, show access rights for the `ConfigMap` called `ingress-controller-leader-nginx` in namespace `ingress-nginx` (note the subtle difference for `nginx-ingress-serviceaccount` to the previous example):

![rakkess demo](doc/demo-named-resource-smaller.png "rakkess resource configmap ingress-controller-leader-nginx --namespace ingress-nginx")
  
As `rakkess resource` needs to query `Roles`, `ClusterRoles`, and their bindings, it usually requires administrative cluster access.

Also see [Usage](doc/USAGE.md).

## Installation
There are several ways to install `rakkess`. The recommended installation method is via `krew`.

### Via krew
Krew is a `kubectl` plugin manager. If you have not yet installed `krew`, get it at
[https://github.com/kubernetes-sigs/krew](https://github.com/kubernetes-sigs/krew).
Then installation is as simple as
```bash
kubectl krew install access-matrix
```
The plugin will be available as `kubectl access-matrix`, see [doc/USAGE](doc/USAGE.md) for further details.

### Binaries
When using the binaries for installation, also have a look at [doc/USAGE](doc/USAGE.md).

#### Linux
```bash
curl -LO https://github.com/corneliusweig/rakkess/releases/download/v0.5.0/rakkess-amd64-linux.tar.gz \
  && tar xf rakkess-amd64-linux.tar.gz rakkess-amd64-linux \
  && chmod +x rakkess-amd64-linux \
  && mv -i rakkess-amd64-linux $GOPATH/bin/rakkess
```

#### OSX
```bash
curl -LO https://github.com/corneliusweig/rakkess/releases/download/v0.5.0/rakkess-amd64-darwin.tar.gz \
  && tar xf rakkess-amd64-darwin.tar.gz rakkess-amd64-darwin \
  && chmod +x rakkess-amd64-darwin \
  && mv -i rakkess-amd64-darwin $GOPATH/bin/rakkess
```

#### Windows
[https://github.com/corneliusweig/rakkess/releases/download/v0.5.0/rakkess-windows-amd64.zip](https://github.com/corneliusweig/rakkess/releases/download/v0.5.0/rakkess-windows-amd64.zip)

### From source

#### Build on host

Requirements:
 - go 1.26 or newer
 - GNU make
 - git

Compiling:
```bash
make all   # checks and a host binary (./rakkess)

# Cross-compile the release artifacts for every supported platform.
make deploy
```

The Kind end-to-end suite requires Docker, `kubectl`, `kind`, and Helm. It
creates and removes only the `rakkess-e2e-20260927` cluster. Run it with
`make e2e`.

#### Build in docker
Requirements:
 - docker

Compiling:
```bash
git clone https://github.com/corneliusweig/rakkess.git
cd rakkess
docker build . -t rakkess-builder
docker run --rm -v "$PWD/out:/go/bin" rakkess-builder
```
Binaries will be placed in `out/`.

## Users

| What are others saying about rakkess? |
| ---- |
| _“Well, that looks handy! `rakkess`, a kubectl plugin to show an access matrix for all available resources.”_ – [@mhausenblas](https://twitter.com/mhausenblas/status/1100673166303739905) |
| _“that's indeed pretty helpful. `rakkess --as system:serviceaccount:my-ns:my-sa -n my-ns` prints the access matrix of a service account in a namespace”_ – [@fakod](https://twitter.com/fakod/status/1100764745957658626) |
| _“THE BOMB. Love it.”_ – [@ralph_squillace](https://twitter.com/ralph_squillace/status/1100844255830896640) |
| _“This made my day. Well, not actually today but I definitively will use it a lot.”_ – [@Soukron](https://twitter.com/Soukron/status/1100690060129775617) |

---

<a name="credit-kubectl-who-can">[1]</a>: This mode was inspired by [kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can)

## Auth-operator provenance

Use `--auth-operator` with the access matrix or `--diff-with` to inspect related
[auth-operator](https://github.com/telekom/auth-operator) configuration and observed
RBAC alongside the effective permissions:

```sh
rakkess --namespace payments --sa payments:reader --auth-operator
rakkess --namespace payments --as alice --as-group readers \
  --diff-with as-group=writers --auth-operator
```

The table on stdout is always calculated using Kubernetes SelfSubjectAccessReviews.
A single-line JSON object on stderr contains `authOperator.original` and, for comparisons,
`authOperator.modified` (ordinary client warnings can also appear on stderr). Each report resolves the effective identity using a
SelfSubjectReview and includes relevant BindDefinitions, RoleDefinitions, observed
managed bindings, referenced roles and native ClusterRole aggregation inputs.
Namespace selectors use OR between selectors and AND within each selector;
explicit namespaces take precedence. Namespaced bindings do not imply cluster-wide
access. Desired configuration may not yet be reconciled and never grants access by
itself.

Reports are advisory. `complete` describes successful reads and decoding of the
supported resources, not a complete explanation of every Kubernetes authorizer.
Missing permissions, incomplete discovery, invalid selectors or unmatched observed
bindings produce `complete: false` with `errors`; unknown selector results are
omitted. RestrictedBindDefinitions, RestrictedRoleDefinitions, RBACPolicy and
external authorizers are not interpreted. Their effective access still appears in
the native SSAR table. Collection uses the same credentials and impersonation as
the matrix, so it cannot disclose metadata the queried identity cannot read.

Authorization evaluation errors appear as `ERR`, including in comparisons. A
resource or verb missing from either comparison inventory also appears as `ERR`;
it is not treated as a denial. Repeated `--diff-with as-group=...` values replace
the original group list and accumulate the new groups.

## End-to-end tests

`make e2e` creates and removes an isolated Kind cluster. It requires Docker, Kind,
Helm, kubectl and jq, plus a clean auth-operator checkout at
`233d42191da159cbe21bf340829ef3f4be9a3ec5` (`v0.5.0-rc.9`):

```sh
AUTH_OPERATOR_DIR=/path/to/auth-operator make e2e
```

The suite builds and runs the real operator, waits for generated roles and bindings,
and checks effective namespace/cluster permissions, service account groups,
permission gains/losses, selector OR/AND behavior, protected namespace exclusion,
ClusterRole aggregation and incomplete provenance. It refuses to reuse an existing
cluster. `KIND_CLUSTER` and `KIND_NODE_IMAGE` can select the task cluster name and
node image. GitHub Actions runs this suite on Kubernetes 1.35 and 1.37, alongside
native Linux, macOS and Windows Go 1.26/1.27 tests. HTTP regression tests exercise
API errors, partial discovery, differing resource inventories and cancellation.
