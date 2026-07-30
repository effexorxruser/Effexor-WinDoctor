package read

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

type registryEntry struct {
	descriptor  domain.OperationDescriptor
	targetTypes []string
	handler     handlerFunc
}

// Registry is an immutable catalog of typed read-only operations.
type Registry struct {
	entries  map[string]registryEntry
	order    []string
	verifier StoreVerifier
}

type registryConfig struct {
	verifier StoreVerifier
}

// Option configures Registry construction.
type Option func(*registryConfig)

// WithStoreVerifier supplies the default Case Store verifier for verify operations.
func WithStoreVerifier(verifier StoreVerifier) Option {
	return func(cfg *registryConfig) {
		cfg.verifier = verifier
	}
}

// NewRegistry builds the PR #18 read-only operation registry.
func NewRegistry(opts ...Option) (*Registry, error) {
	cfg := registryConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	handlers := defaultHandlers()
	entries := make(map[string]registryEntry, len(catalogEntries()))
	order := make([]string, 0, len(catalogEntries()))
	for _, item := range catalogEntries() {
		key := entryKey(item.descriptor.OperationID, item.descriptor.Version)
		if _, dup := entries[key]; dup {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateOperation, key)
		}
		handler, ok := handlers[item.descriptor.OperationID]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrMissingHandler, item.descriptor.OperationID)
		}
		if err := validateDescriptor(item.descriptor, item.targetTypes, handler); err != nil {
			return nil, err
		}
		entries[key] = registryEntry{
			descriptor:  item.descriptor,
			targetTypes: append([]string(nil), item.targetTypes...),
			handler:     handler,
		}
		order = append(order, key)
	}
	sort.Strings(order)
	return &Registry{entries: entries, order: order, verifier: cfg.verifier}, nil
}

// Descriptor returns one operation descriptor by id and version.
func (r *Registry) Descriptor(operationID, version string) (domain.OperationDescriptor, bool) {
	entry, ok := r.entries[entryKey(operationID, version)]
	if !ok {
		return domain.OperationDescriptor{}, false
	}
	return cloneDescriptor(entry.descriptor), true
}

// Descriptors returns a defensive deep copy of all registered descriptors.
func (r *Registry) Descriptors() []domain.OperationDescriptor {
	out := make([]domain.OperationDescriptor, 0, len(r.order))
	for _, key := range r.order {
		entry := r.entries[key]
		out = append(out, cloneDescriptor(entry.descriptor))
	}
	return out
}

func cloneDescriptor(d domain.OperationDescriptor) domain.OperationDescriptor {
	out := d
	out.RequiredEvidence = append([]string(nil), d.RequiredEvidence...)
	out.RequiredCapabilities = append([]string(nil), d.RequiredCapabilities...)
	out.SupportedRuntimes = append([]string(nil), d.SupportedRuntimes...)
	if out.RequiredEvidence == nil {
		out.RequiredEvidence = []string{}
	}
	if out.RequiredCapabilities == nil {
		out.RequiredCapabilities = []string{}
	}
	if out.SupportedRuntimes == nil {
		out.SupportedRuntimes = []string{}
	}
	return out
}

// Execute runs one typed read-only operation against Case snapshot or store context.
func (r *Registry) Execute(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	entry, ok := r.entries[entryKey(request.OperationID, request.OperationVersion)]
	if !ok {
		if hasOperationID(r, request.OperationID) {
			return Result{}, ErrUnknownVersion
		}
		return Result{}, ErrUnknownOperation
	}
	target, params, err := validateExecuteRequest(request, entry)
	if err != nil {
		return Result{}, err
	}
	idx, err := buildSnapshotIndex(request.Snapshot)
	if err != nil {
		return Result{}, err
	}
	verifier := request.StoreVerifier
	if verifier == nil {
		verifier = r.verifier
	}
	env := execContext{
		request:   request,
		target:    target,
		params:    params,
		index:     idx,
		verifier:  verifier,
		operation: entry.descriptor,
	}
	result, err := entry.handler(ctx, env)
	if err != nil {
		return Result{}, err
	}
	if err := validateResultAgainstRequest(request, result); err != nil {
		return Result{}, err
	}
	if err := validateSourceEvidence(result, idx); err != nil {
		return Result{}, err
	}
	return Result{ReadOperationResult: result}, nil
}

func entryKey(operationID, version string) string {
	return operationID + "@" + version
}

func hasOperationID(r *Registry, operationID string) bool {
	prefix := operationID + "@"
	for _, key := range r.order {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func validateCatalogEntry(desc domain.OperationDescriptor, targetTypes []string, handler handlerFunc) error {
	return validateDescriptor(desc, targetTypes, handler)
}

func defaultHandlers() map[string]handlerFunc {
	return map[string]handlerFunc{
		"windows.inspect_installation":     handleInspectWindowsInstallation,
		"boot.inspect_firmware_mode":       handleInspectFirmwareMode,
		"boot.inspect_bcd_store":           handleInspectBCDStore,
		"boot.inspect_efi_layout":          handleInspectEFILayout,
		"storage.inspect_disk_health":      handleInspectDiskHealth,
		"storage.inspect_partition_layout": handleInspectPartitionLayout,
		"bitlocker.inspect_inventory":      handleInspectBitLockerInventory,
		"case.verify_store_integrity":      handleVerifyStoreIntegrity,
	}
}
