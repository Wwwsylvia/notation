package auth

import (
	"fmt"

	"github.com/notaryproject/notation-go/dir"
	credentials "github.com/oras-project/oras-credentials-go"
)

// NewCredentialsStore returns a new credentials store from the settings in the
// configuration file.
func NewCredentialsStore() (credentials.Store, error) {
	configPath, err := dir.ConfigFS().SysPath(dir.PathConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	opts := credentials.StoreOptions{AllowPlaintextPut: false}
	notationStore, err := credentials.NewStore(configPath, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store from config file: %w", err)
	}

	dockerStore, err := credentials.NewStoreFromDocker(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store from docker config file: %w", err)
	}

	if !notationStore.IsAuthConfigured() && !dockerStore.IsAuthConfigured() {
		// if both notation config and docker config do not have auth
		// configuration, fallback to the platform-default credentials helper
		// (if available)
		osDefaultStore, ok := credentials.NewDefaultNativeStore()
		if ok {
			return credentials.NewStoreWithFallbacks(notationStore, dockerStore, osDefaultStore), nil
		}
	}
	return credentials.NewStoreWithFallbacks(notationStore, dockerStore), nil
}
