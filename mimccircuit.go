package main

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const (
	ROUNDS  = 10
	depth   = 15 // Merkle tree depth
	PathNum = 4  // number of Merkle path needs to check for 1 transaction
	UserNum = 1  // number of users. The total hashes need to be checked is depth * PathNum * UserNum
)

type MiMcCircuit struct {
	curveID     tedwards.ID
	Message     []frontend.Variable `gnark:",public"`
	HashOutputs []frontend.Variable `gnark:",public"`
}

func (circuit *MiMcCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	var temp frontend.Variable
	// verify the signature in the cs
	for k := 0; k < UserNum; k++ {
		for j := 0; j < PathNum; j++ {
			for i := 0; i < depth; i++ {
				mimc.Write(circuit.Message[i])
				temp = mimc.Sum()
				api.AssertIsEqual(temp, circuit.HashOutputs[i])
				mimc.Reset()
			}
		}
	}
	return err
}

// GetMiMcAssign generate a test assignment of circuit for Testing!
func GetMiMcAssign() *MiMcCircuit {
	hash := hash.MIMC_BN254.New()

	msg := make([]byte, 32)
	msg[0] = 0x0d
	hash.Write(msg)
	var assignment MiMcCircuit
	hashOut := hash.Sum(nil)
	// assign message value
	assignment.Message = make([]frontend.Variable, depth)
	assignment.HashOutputs = make([]frontend.Variable, depth)
	// assign public key values
	for k := 0; k < UserNum; k++ {
		for j := 0; j < PathNum; j++ {
			for i := 0; i < depth; i++ {
				assignment.Message[i] = msg
				assignment.HashOutputs[i] = hashOut
			}
		}
	}
	return &assignment
}

func GetEmptyMiMcAssign() *MiMcCircuit {
	hash := hash.MIMC_BN254.New()

	msg := make([]byte, 32)
	msg[0] = 0x0d
	hash.Write(msg)
	var assignment MiMcCircuit
	hashOut := hash.Sum(nil)
	// assign message value
	assignment.Message = make([]frontend.Variable, depth)
	assignment.HashOutputs = make([]frontend.Variable, depth)
	// assign public key values
	for k := 0; k < UserNum; k++ {
		for j := 0; j < PathNum; j++ {
			for i := 0; i < depth; i++ {
				assignment.Message[i] = msg
				assignment.HashOutputs[i] = hashOut
			}
		}
	}
	return &assignment
}
