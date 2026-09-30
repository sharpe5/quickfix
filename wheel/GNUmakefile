# Build the quickfix Python extension from this checkout -- TLS on, certificate hostname
# verification on -- and install it into whichever python is active:
#
#   make -C wheel install
#
# Named GNUmakefile, in a subdirectory, because the repository's ignore rules cover every file
# called Makefile (./configure writes one at the root). GNU make reads this name first, and
# nothing else here has a reason to.
#
# Prerequisites: a C++ toolchain, Python.h and the OpenSSL headers.
#   macOS   xcode-select --install && brew install openssl@3
#   Debian  apt-get install -y build-essential python3-dev libssl-dev
PYTHON ?= python
REPOSITORY := $(abspath ..)

.DEFAULT_GOAL := help
.PHONY: help install wheel verify clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf "\n  PYTHON=%s  (the interpreter to install into; defaults to the active one)\n" "$(PYTHON)"

# --no-cache-dir and --force-reinstall: pip must not hand back a wheel it built earlier from a
# different commit, and a re-run after a pull must replace what is installed.
install: ## Build from this checkout and install into the ACTIVE python, then verify
	@$(PYTHON) -c "import sys; print('Installing quickfix from $(REPOSITORY) ($(shell git -C $(REPOSITORY) rev-parse --short HEAD)) into', sys.prefix)"
	$(PYTHON) -m pip install --no-deps --force-reinstall --no-cache-dir "$(REPOSITORY)"
	@$(MAKE) --no-print-directory verify

wheel: ## Build a wheel into ../dist without installing it
	$(PYTHON) -m pip wheel --no-deps --no-cache-dir --wheel-dir "$(REPOSITORY)/dist" "$(REPOSITORY)"

verify: ## Prove the installed quickfix rejects a certificate issued for the wrong name (loopback only)
	$(PYTHON) verify_hostname_check.py

clean: ## Remove build output
	rm -rf "$(REPOSITORY)/build" "$(REPOSITORY)/dist" "$(REPOSITORY)/src/python/quickfix.egg-info" __pycache__
