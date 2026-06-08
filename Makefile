# Oubliette monorepo — common dev tasks.
# Thin wrapper over the pinned SDK (fvm) + the Melos workspace scripts, so day-to-day
# work is `make test` rather than `fvm exec dart run melos run test`.
#
# Toolchain prefix. Defaults to `fvm exec` (pinned Flutter 3.44.1 / Dart 3.12.1).
# On a machine/CI where the right Dart+Flutter are already on PATH, override it:
#   make test RUNNER=
RUNNER ?= fvm exec
MELOS  := $(RUNNER) dart run melos

.DEFAULT_GOAL := help
.PHONY: help get analyze test format format-fix kotlin-test apk integration ci clean

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-13s\033[0m %s\n",$$1,$$2}'

get: ## Resolve the whole workspace (one pub get from the root)
	$(RUNNER) flutter pub get

analyze: ## Analyze every package (fails on any issue)
	$(MELOS) run analyze

test: ## Run Dart unit tests in every package that has tests
	$(MELOS) run test

format: ## Check Dart formatting across all packages
	$(MELOS) run format

format-fix: ## Apply Dart formatting across all packages
	$(MELOS) run format:fix

kotlin-test: ## Run the Kotlin JVM unit tests (via the example Gradle build)
	cd oubliette/example/android && ./gradlew :keystore:testDebugUnitTest

apk: ## Build the example debug APK (compiles all plugin Kotlin)
	cd oubliette/example && $(RUNNER) flutter build apk --debug

integration: ## Run integration tests (needs a connected device/emulator)
	cd oubliette/example && $(RUNNER) flutter test integration_test/

ci: get analyze test ## What CI runs for the Dart workspace

clean: ## Remove Flutter build artifacts across the workspace
	$(MELOS) exec -- flutter clean

