KEYCLOAK_VERSION ?= 26.8.0
QUALIFICATION_DIR ?=
.PHONY: test integration-test keycloak-extension-build keycloak-extension-test
test:
	mvn -B -ntp -Dkeycloak.version=$(KEYCLOAK_VERSION) verify
integration-test:
	python3 scripts/qualify.py --keycloak-version $(KEYCLOAK_VERSION) --harness "$(QUALIFICATION_DIR)"
keycloak-extension-build: test
keycloak-extension-test: integration-test

.PHONY: hook-tools hooks-check policy-check
hook-tools:
	python3 scripts/install-hook-tools.py .tools/hook-tools
hooks-check:
	python3 .tools/hook-tools/pre-commit.pyz run --all-files --show-diff-on-failure
policy-check:
	python3 scripts/check-rulesets.py
	python3 -m unittest discover -s scripts -p 'test_*.py'
