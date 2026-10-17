KEYCLOAK_VERSION ?= 26.8.0
QUALIFICATION_DIR ?=
MAVEN_REPO_LOCAL ?= $(CURDIR)/.tools/maven
MAVEN_USER_HOME ?= $(CURDIR)/.tools/maven-user
RELEASE_ASSETS ?= 0
export MAVEN_REPO_LOCAL MAVEN_USER_HOME
.DEFAULT_GOAL := test
.PHONY: test integration-test consumer-test release-dry-run keycloak-extension-build keycloak-extension-test hook-tools hooks-check policy-check
test:
	./mvnw -B -ntp -Dmaven.repo.local="$(MAVEN_REPO_LOCAL)" -Dkeycloak.version=$(KEYCLOAK_VERSION) verify
integration-test:
	python3 scripts/qualify.py --keycloak-version $(KEYCLOAK_VERSION) $(if $(filter 1,$(RELEASE_ASSETS)),--release-assets)
consumer-test:
	python3 scripts/consumer-interop.py --keycloak-version $(KEYCLOAK_VERSION) --harness "$(QUALIFICATION_DIR)"
release-dry-run:
	python3 scripts/qualify.py --keycloak-version $(KEYCLOAK_VERSION) --release-assets
	python3 scripts/release.py package --keycloak-version $(KEYCLOAK_VERSION) --output target/$(KEYCLOAK_VERSION)/release-dry-run --dry-run
keycloak-extension-build: test
keycloak-extension-test: integration-test
hook-tools:
	python3 scripts/install-hook-tools.py .tools/hook-tools
hooks-check:
	python3 .tools/hook-tools/pre-commit.pyz run --all-files --show-diff-on-failure
policy-check:
	python3 scripts/check-rulesets.py
	python3 scripts/check-project.py
	python3 -m unittest discover -s scripts -p 'test_*.py'
