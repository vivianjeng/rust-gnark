// gen_test_vectors compiles a simple cubic circuit (x^3 + x + 5 == y),
// runs Groth16 trusted setup, and exports .r1cs, .pk, .vk files to
// ../../tests/test-vectors/ for use in Rust integration tests.
//
// Usage: go run ./cmd/gen_test_vectors
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CubicCircuit defines x^3 + x + 5 == y
type CubicCircuit struct {
	X frontend.Variable `gnark:"X"`
	Y frontend.Variable `gnark:"Y,public"`
}

func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	sum := api.Add(x3, circuit.X, 5)
	api.AssertIsEqual(sum, circuit.Y)
	return nil
}

func main() {
	outDir := filepath.Join("..", "tests", "test-vectors")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(fmt.Sprintf("failed to create output dir: %v", err))
	}

	var circuit CubicCircuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Sprintf("failed to compile circuit: %v", err))
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(fmt.Sprintf("failed to run setup: %v", err))
	}

	r1csFile, err := os.Create(filepath.Join(outDir, "cubic_circuit.r1cs"))
	if err != nil {
		panic(fmt.Sprintf("failed to create r1cs file: %v", err))
	}
	defer r1csFile.Close()
	if _, err := cs.WriteTo(r1csFile); err != nil {
		panic(fmt.Sprintf("failed to write r1cs: %v", err))
	}

	// WriteRawTo produces uncompressed binary, paired with UnsafeReadFrom on load
	pkFile, err := os.Create(filepath.Join(outDir, "cubic_circuit.pk"))
	if err != nil {
		panic(fmt.Sprintf("failed to create pk file: %v", err))
	}
	defer pkFile.Close()
	if _, err := pk.WriteRawTo(pkFile); err != nil {
		panic(fmt.Sprintf("failed to write pk: %v", err))
	}

	vkFile, err := os.Create(filepath.Join(outDir, "cubic_circuit.vk"))
	if err != nil {
		panic(fmt.Sprintf("failed to create vk file: %v", err))
	}
	defer vkFile.Close()
	if _, err := vk.WriteTo(vkFile); err != nil {
		panic(fmt.Sprintf("failed to write vk: %v", err))
	}

	fmt.Println("Test vectors generated successfully in", outDir)
}
