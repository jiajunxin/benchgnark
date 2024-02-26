package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
)

func referenceCircuit(curve ecc.ID) (constraint.ConstraintSystem, frontend.Circuit, kzg.SRS) {
	circuit := GetEmptyMiMcAssign()
	ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}
	//snarkField, _ := twistededwards.GetSnarkField(tedwards.BN254)
	assignedCircuit := GetMiMcAssign()

	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic(err)
	}
	return ccs, assignedCircuit, srs
}

func main() {
	snarkField, _ := twistededwards.GetSnarkField(tedwards.BN254)

	ccs, _ := frontend.Compile(snarkField, r1cs.NewBuilder, GetEmptyMiMcAssign())
	ccs.GetNbConstraints()
	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)
	witness, err := frontend.NewWitness(GetMiMcAssign(), snarkField)
	if err != nil {
		fmt.Println("Error = ", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("Error = ", err)
	}
	// generate the proof
	runtime.GC()
	startingTime := time.Now().UTC()
	for i := 0; i < ROUNDS; i++ {
		_, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			fmt.Println("Error = ", err)
		}
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Groth16! Generating proofs for Merkle path verify for %d depth, %d PathNum and %d users, takes [%.3f] Seconds, for 10 run!\n", depth, PathNum, UserNum, duration.Seconds())
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println("Error = ", err)
	}
	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Error = ", err)
	}
	runtime.GC()
	// Plonk zkSNARK: Setup
	ccs, _solution, srs := referenceCircuit(ecc.BN254)
	fullWitness, err := frontend.NewWitness(_solution, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("Error = ", err)
	}
	pk2, vk2, err := plonk.Setup(ccs, srs)
	if err != nil {
		fmt.Println("Error = ", err)
	}
	runtime.GC()
	startingTime = time.Now().UTC()
	for i := 0; i < ROUNDS; i++ {
		_, err = plonk.Prove(ccs, pk2, fullWitness)
		if err != nil {
			fmt.Println("Error = ", err)
		}
	}
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Plonk! Generating proofs for Merkle path verify for %d depth, %d PathNum and %d users, takes [%.3f] Seconds, for 10 run!\n", depth, PathNum, UserNum, duration.Seconds())

	proof2, err := plonk.Prove(ccs, pk2, fullWitness)
	if err != nil {
		fmt.Println("Error = ", err)
	}
	publicWitness2, err := fullWitness.Public()
	if err != nil {
		fmt.Println("Error = ", err)
	}
	_ = plonk.Verify(proof2, vk2, publicWitness2)

}
