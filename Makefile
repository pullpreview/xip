SHELL := /bin/bash

BINARY := xip
GO ?= mise x -- go
GOSUMDB ?= sum.golang.org

DIST_DIR := dist
BUILD_OUTPUT := $(DIST_DIR)/$(BINARY)
LINUX_AMD64_OUTPUT := $(DIST_DIR)/$(BINARY)-linux-amd64

SYSTEMD_UNIT_LOCAL := deploy/$(BINARY).service
LOGROTATE_LOCAL := deploy/$(BINARY).logrotate
LOCAL_ENV_FILE := config/.env

REMOTE_BIN ?= /usr/local/bin/$(BINARY)
REMOTE_SYSTEMD_UNIT ?= /etc/systemd/system/$(BINARY).service
REMOTE_ENV_FILE ?= /etc/default/$(BINARY)
REMOTE_LOGROTATE ?= /etc/logrotate.d/$(BINARY)
REMOTE_TMP_DIR ?= /tmp/$(BINARY)-deploy

SSH_USER ?= root
SSH_PORT ?= 22
SERVER_IP ?=
SERVER ?=
TARGET_HOST := $(if $(SERVER_IP),$(SERVER_IP),$(SERVER))
SSH_TARGET := $(SSH_USER)@$(TARGET_HOST)
SSH := ssh -p $(SSH_PORT)
SCP := scp -P $(SSH_PORT)

.PHONY: build build-linux-amd64 test run deploy clean
.PHONY: fmt check-fmt lint precommit-install precommit-run

build:
	mkdir -p $(DIST_DIR)
	GOSUMDB=$(GOSUMDB) $(GO) build -trimpath -o $(BUILD_OUTPUT) ./cmd/$(BINARY)

build-linux-amd64:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOSUMDB=$(GOSUMDB) $(GO) build -trimpath -ldflags='-s -w' -o $(LINUX_AMD64_OUTPUT) ./cmd/$(BINARY)

test:
	GOSUMDB=$(GOSUMDB) $(GO) test ./...

fmt:
	GOSUMDB=$(GOSUMDB) $(GO) fmt ./...

check-fmt:
	@unformatted="$$(mise x -- gofmt -l $$(git ls-files '*.go'))"; \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted Go files:"; \
		echo "$$unformatted"; \
		echo "Run: make fmt"; \
		exit 1; \
	fi

lint:
	GOSUMDB=$(GOSUMDB) $(GO) vet ./...

run:
	GOSUMDB=$(GOSUMDB) $(GO) run ./cmd/$(BINARY)

deploy: build-linux-amd64
	@test -n "$(TARGET_HOST)" || (echo "Set SERVER_IP=<server ip> (or SERVER=<server ip>)" && exit 1)
	@test -f "$(LOCAL_ENV_FILE)" || (echo "Missing $(LOCAL_ENV_FILE). Create it from config/.env.example first." && exit 1)
	$(SSH) $(SSH_TARGET) "mkdir -p $(REMOTE_TMP_DIR)"
	$(SCP) $(LINUX_AMD64_OUTPUT) $(SSH_TARGET):$(REMOTE_TMP_DIR)/$(BINARY)
	$(SCP) $(SYSTEMD_UNIT_LOCAL) $(SSH_TARGET):$(REMOTE_TMP_DIR)/$(BINARY).service
	$(SCP) $(LOGROTATE_LOCAL) $(SSH_TARGET):$(REMOTE_TMP_DIR)/$(BINARY).logrotate
	$(SCP) $(LOCAL_ENV_FILE) $(SSH_TARGET):$(REMOTE_TMP_DIR)/$(BINARY).env
	$(SSH) $(SSH_TARGET) "sudo install -m 0755 $(REMOTE_TMP_DIR)/$(BINARY) $(REMOTE_BIN) && \
		sudo install -m 0644 $(REMOTE_TMP_DIR)/$(BINARY).service $(REMOTE_SYSTEMD_UNIT) && \
		sudo install -m 0644 $(REMOTE_TMP_DIR)/$(BINARY).logrotate $(REMOTE_LOGROTATE) && \
		sudo install -m 0644 $(REMOTE_TMP_DIR)/$(BINARY).env $(REMOTE_ENV_FILE) && \
		sudo install -d -m 0755 /var/log/$(BINARY) && \
		sudo touch /var/log/$(BINARY)/$(BINARY).log && \
		sudo chmod 0640 /var/log/$(BINARY)/$(BINARY).log && \
		sudo systemctl daemon-reload && \
		sudo systemctl enable --now $(BINARY).service && \
		sudo systemctl restart $(BINARY).service && \
		rm -rf $(REMOTE_TMP_DIR)"

clean:
	rm -rf $(DIST_DIR)

precommit-install:
	pre-commit install --install-hooks --hook-type pre-commit

precommit-run:
	pre-commit run --all-files
