# HELP ########################################################################
.DEFAULT_GOAL := help

.PHONY: help
help:
	@ printf "\nusage : make <commands> \n\nthe following commands are available : \n\n"
	@ grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sed -e "s/^Makefile://" | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


# APP ########################################################################

# Project settings
PROJECT := aia_chaser
PACKAGE := aia_chaser
PYTHON_VERSION=3.8

# Style makefile outputs
ECHO_COLOUR=\033[0;34m
NC=\033[0m # No Color

# Project paths
PACKAGES := $(PACKAGE) tests
CONFIG := $(wildcard *.py)
MODULES := $(wildcard $(PACKAGE)/*.py)

# Virtual environment paths
VIRTUAL_ENV ?= .venv

# SYSTEM DEPENDENCIES #########################################################

.PHONY: doctor
doctor:  ## Confirm system dependencies are available
	scripts/verchew --exit-code --root="${CURDIR}/scripts"

# PROJECT DEPENDENCIES ########################################################

DEPENDENCIES := $(VIRTUAL_ENV)/.poetry-$(shell scripts/checksum pyproject.toml poetry.lock)
TOOLS_FIRST_INSTALLED := $(VIRTUAL_ENV)/.tools_first_installed

.PHONY:
init: $(VIRTUAL_ENV) install-dev install-test $(TOOLS_FIRST_INSTALLED)

.PHONY: install
install: $(DEPENDENCIES) .cache

.PHONY: install-test
install-test: install
	poetry install --with test

.PHONY: install-dev
install-dev: install
	poetry install --with dev

.PHONY: install-docs
install-docs: install
	poetry install --with docs

$(DEPENDENCIES):
	poetry install --no-root
	@ touch $@
	@ $(MAKE) gen-req

$(TOOLS_FIRST_INSTALLED): .git
	@ poetry run pre-commit install
	@ poetry run git config commit.template .gitmessage
	@ poetry self add poetry-plugin-export
	@ touch $@ # This will create a file named `.tools_first_installed` inside venv folder

.git:
	git init

.cache:
	@ mkdir -p .cache

$(VIRTUAL_ENV): ## Create python environment
	$(MAKE) doctor
	@ echo "$(ECHO_COLOUR)Configuring poetry$(NC)"
	@ poetry config --local virtualenvs.in-project true
	@ poetry config --local virtualenvs.prefer-active-python true
	@ echo "$(ECHO_COLOUR)Initializing pyenv$(NC)"
	$(eval PYENV_LATEST_VERSION=$(shell pyenv install --list | grep " $(PYTHON_VERSION)\.[0-9]*$$" | tail -1))
	@ echo "$(ECHO_COLOUR)Installing python version $(PYENV_LATEST_VERSION)...$(NC)"
	pyenv install -s $(PYENV_LATEST_VERSION)
	pyenv local $(PYENV_LATEST_VERSION)

.PHONY: gen-req
gen-req:  ## Generate requirements files from poetry
	@ echo "$(ECHO_COLOUR)Updating requirements files$(NC)"
	poetry export -f requirements.txt --without-hashes > requirements.txt
	poetry export -f requirements.txt --without-hashes --with dev > requirements-dev.txt
	poetry export -f requirements.txt --without-hashes --with test > requirements-test.txt
	@ poetry run scripts/req_fixer requirements.txt requirements-dev.txt requirements-test.txt


# CHECKS ######################################################################

.PHONY: format
format:  ## Run formatters
	poetry run isort $(PACKAGES)
	poetry run black $(PACKAGES)
	@ echo

.PHONY: check
check:  ## Run linters, and static code analysis
	poetry run safety check -r requirements.txt
	@ echo
	poetry run mypy --install-types --non-interactive $(PACKAGES)
	@ echo
	poetry run flake8 $(PACKAGES)

.PHONY: pre-commit
pre-commit:  ## Run pre-commit on all files
	poetry run pre-commit run --all-files


# TESTS #######################################################################

RANDOM_SEED ?= $(shell date +%s)
FAILURES := .cache/v/cache/lastfailed

PYTEST_OPTIONS := -v --randomly-seed=$(RANDOM_SEED)
ifndef DISABLE_COVERAGE
PYTEST_OPTIONS += --cov=$(PACKAGE)
endif
ifdef EXTRA_ARG
PYTEST_OPTIONS += $(EXTRA_ARG)
endif
ifdef DEBUG
PYTEST_OPTIONS += --pdb
endif

PYTEST_RERUN_OPTIONS := -v --randomly-seed=last

.PHONY: test
test: test-all ## Run unit and integration tests

.PHONY: test-all
test-all: install-test
	@ if test -e $(FAILURES); then poetry run pytest $(PYTEST_RERUN_OPTIONS); fi
	@ rm -rf $(FAILURES)
	poetry run pytest $(PYTEST_OPTIONS)

.PHONY: read-coverage
read-coverage:  ## Open last coverage report in html page
	scripts/open htmlcov/index.html


# DOCUMENTATION ###############################################################

# VERSIONING ##################################################################

.PHONY: bump-minor
bump-minor:
	poetry run bump-my-version bump minor

.PHONY: bump-major
bump-major:
	poetry run bump-my-version bump major

.PHONY: bump-patch
bump-patch:
	poetry run bump-my-version bump patch


# BUILD #######################################################################

DIST_FILES := dist/*.tar.gz dist/*.whl
EXE_FILES := dist/$(PROJECT).*

.PHONY: dist
dist: install $(DIST_FILES)
$(DIST_FILES): $(MODULES) pyproject.toml
	rm -f $(DIST_FILES)
	poetry build

# .PHONY: exe
# exe: install $(EXE_FILES)
# $(EXE_FILES): $(MODULES) $(PROJECT).spec
# 	# For framework/shared support: https://github.com/yyuu/pyenv/wiki
# 	poetry run pyinstaller $(PROJECT).spec --noconfirm --clean

# $(PROJECT).spec:
# 	poetry run pyi-makespec $(PACKAGE)/__main__.py --onefile --windowed --name=$(PROJECT)



# CLEANUP #####################################################################

.PHONY: clean
clean: .clean-build .clean-docs .clean-test .clean-install ## Delete all generated and temporary files

.PHONY: clean-all
clean-all: clean
	rm -rf $(VIRTUAL_ENV)

.PHONY: .clean-install
.clean-install:
	find $(PACKAGES) -name '__pycache__' -delete
	rm -rf *.egg-info

.PHONY: .clean-test
.clean-test:
	rm -rf .cache .pytest .coverage htmlcov

.PHONY: .clean-docs
.clean-docs:
	rm -rf site

.PHONY: .clean-build
.clean-build:
	rm -rf *.spec dist build


# MAIN TASKS ##################################################################

.PHONY: all
all: install

.PHONY: ci
ci: install-dev format check test ## Run all tasks that determine CI status

.PHONY: run
run: install ## Start the program
	poetry run python $(PACKAGE)/__main__.py
