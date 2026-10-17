# Hanko consumer integration

Hanko is an external consumer of this generic Keycloak extension. Its operator
resolves Kubernetes references and ownership, writes administrative grants and
recovers its Prepared/Applied/Verified/Committed transaction. Those concerns are
not dependencies of the provider or the proposed native Keycloak controls.

[compatibility.json](../../compatibility.json) retains the exact historical
consumer harness revision and named outcomes. To run its optional real HTTPS
interop tests, provide a clean checkout of that revision:

```sh
make consumer-test KEYCLOAK_VERSION=26.8.0 QUALIFICATION_DIR=/path/to/pinned/hankoshell-operator
```

The extension source and JAR are built here. The Go/race/controller harness runs
in the consumer checkout and records both revisions and the artifact hash.
The consumer workflow is manual/weekly; the main extension CI needs no checkout
or credentials for Hanko. Installed Kubernetes and consumer workload qualification
remain tracked in [Hanko #71](https://github.com/Alien6-Studio/hankoshell-operator/issues/71).

Hanko pins its own reviewed extension commit. A release here does not silently
upgrade or enable a consumer's deployment. The software-v1 administrative wire
contract is retained while the upstream design is discussed independently.
