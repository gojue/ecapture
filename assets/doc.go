package assets

import "fmt"

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or could not be loaded.
// This stub will be replaced by the actual generated assets during build.
func Asset(name string) ([]byte, error) {
	return nil, fmt.Errorf("asset %s not found (assets not yet generated, run 'make ebpf' first)", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	return []string{}
}
