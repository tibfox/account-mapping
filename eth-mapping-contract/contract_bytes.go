package ethcontracts

import (
	"embed"
	"fmt"
)

//go:embed bin
var artifactsFS embed.FS

const artifactsDir = "bin"

var (
	DevWasm     []byte
	TestnetWasm []byte
)

func init() {
	DevWasm, _ = loadWasmFile("dev.wasm")
	TestnetWasm, _ = loadWasmFile("testnet.wasm")
}

func loadWasmFile(filename string) ([]byte, error) {
	path := fmt.Sprintf("%s/%s", artifactsDir, filename)
	data, err := artifactsFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wasm file not found: %s", filename)
	}
	return data, nil
}
