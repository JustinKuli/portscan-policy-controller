
IMG ?= quay.io/justinkuli/scratchpad:portscan-policy-controller

export PATH := $(PWD)/bin:$(PATH)
# Keep an existing GOPATH, make a private one if it is undefined
GOPATH_DEFAULT := $(PWD)/.go
export GOPATH ?= $(GOPATH_DEFAULT)
GOBIN_DEFAULT := $(GOPATH)/bin
export GOBIN ?= $(GOBIN_DEFAULT)

CONTROLLER_GEN = $(GOBIN)/controller-gen
$(CONTROLLER_GEN):
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.8.0

.PHONY: manifests
manifests: $(CONTROLLER_GEN) ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: $(CONTROLLER_GEN) ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test-unit: manifests generate fmt vet ## Run unit tests.
	echo "no unit tests defined yet"
# go test ./... -coverprofile cover.out

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./main.go

.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	docker build -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push $(IMG)

KUSTOMIZE = $(GOBIN)/kustomize
$(KUSTOMIZE):
	go install sigs.k8s.io/kustomize/kustomize/v4@v4.5.2

.PHONY: install
install: manifests $(KUSTOMIZE) ## Install CRDs into the K8s cluster in your active kubeconfig
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests $(KUSTOMIZE) ## Uninstall CRDs from the K8s cluster in your active kubeconfig
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=true -f -

.PHONY: deploy
deploy: manifests $(KUSTOMIZE) ## Deploy controller to the K8s cluster in your active kubeconfig
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster in your active kubeconfig
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=true -f -

KIND_NAME ?= policy-addon-ctrl1
KIND_KUBECONFIG ?= $(PWD)/$(KIND_NAME).kubeconfig

$(KIND_KUBECONFIG):
	@echo "Creating cluster"
	kind create cluster --name $(KIND_NAME) $(KIND_ARGS)
	kind get kubeconfig --name $(KIND_NAME) > $(KIND_KUBECONFIG)

.PHONY: kind-create-cluster
kind-create-cluster: $(KIND_KUBECONFIG) ## Create a kind cluster.

.PHONY: kind-delete-cluster
kind-delete-cluster: ## Delete a kind cluster.
	@echo "Deleting cluster"
	kind delete cluster --name $(KIND_NAME) || true
	rm $(KIND_KUBECONFIG) || true

.PHONY: kind-load-image
kind-load-image: docker-build $(KIND_KUBECONFIG) ## Build and load the docker image into kind.
	kind load docker-image $(IMG) --name $(KIND_NAME)

.PHONY: regenerate-controller
kind-regenerate-controller: kind-load-image manifests generate $(KUSTOMIZE) $(KIND_KUBECONFIG) ## Refresh (or initially deploy) the policy-addon-controller.
	cp config/default/kustomization.yaml config/default/kustomization.yaml.tmp
	cd config/default && $(KUSTOMIZE) edit set image policy-addon-image=$(IMG)
	KUBECONFIG=$(KIND_KUBECONFIG) $(KUSTOMIZE) build config/default | kubectl apply -f -
	mv config/default/kustomization.yaml.tmp config/default/kustomization.yaml
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl delete -n portscan-policy-controller-system pods -l=app=portscan-policy-controller
