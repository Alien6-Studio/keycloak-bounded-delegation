# Hanko consumer integration

Hanko is an external consumer of this generic Keycloak extension. Its operator
resolves Kubernetes references and ownership, writes administrative grants and
recovers its Prepared/Applied/Verified/Committed transaction. Those concerns are
not dependencies of the provider or the proposed native Keycloak controls.

[compatibility.json](../../compatibility.json) records the exact reviewed
consumer harness revision and named outcomes. To run its optional real HTTPS
interop tests, provide a clean checkout of that revision:

```sh
make consumer-test KEYCLOAK_VERSION=26.8.1 QUALIFICATION_DIR=/path/to/pinned/hankoshell-operator
```

The extension source and JAR are built here. The Go/race/controller harness runs
in the consumer checkout and records both revisions and the artifact hash.
The consumer workflow is manual/weekly; the main extension CI needs no checkout
or credentials for Hanko. Installed Kubernetes and consumer workload qualification
remain tracked in [Hanko #71](https://github.com/Alien6-Studio/hankoshell-operator/issues/71).

Hanko pins its own reviewed extension commit. A release here does not silently
upgrade or enable a consumer's deployment. The software-v1 administrative wire
contract is retained while the upstream design is discussed independently.

The pinned harness covers Keycloak **26.7.5 and 26.8.1** and explicitly accepts
extension rc.2 and 0.1.0 with every existing software/task guard. Its window is
recorded separately under `integrations.hanko.keycloak`. Unsupported consumer
SDKs are rejected before build or Docker access.

The published operator **1.1.0 accepts rc.2 only**. Installing extension 0.1.0 does
not upgrade that operator's compiled capability checks. Keep rc.2 for operator
1.1.0, or use a consumer release that explicitly includes 0.1.0 support. The
new harness is a source interoperability result, not a claim that a new operator
binary has been released. Preserve the database, native identities and journals
through a coordinated maintenance window; no mixed-version rolling upgrade is
qualified.
