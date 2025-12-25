// Copyright (c) Elliot Technologies, Inc.
// SPDX-License-Identifier: BUSL-1.1

package builder

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	gl "github.com/elliottech/gnark-plonky2-verifier/goldilocks"
	"github.com/elliottech/gnark-plonky2-verifier/types"
	"github.com/elliottech/gnark-plonky2-verifier/variables"

	"github.com/elliottech/lighter-prover/snark/circuit"
)

func PlaceHolderPublicInputs(numOfPublicInputs uint64) []gl.Variable {
	return make([]gl.Variable, numOfPublicInputs)
}

func PlaceHolderCommitPhaseMerkleCaps(capHeight uint64, numReductionArityBits int) []variables.FriMerkleCap {
	result := make([]variables.FriMerkleCap, numReductionArityBits)
	for i := range result {
		result[i] = variables.NewFriMerkleCap(capHeight)
	}
	return result
}

func numPreprocessedPolys(c *types.CommonCircuitData) uint64 {
	sigmasRange := sigmasRange(c)
	return sigmasRange[len(sigmasRange)-1]
}

// Range of the sigma polynomials in the `constants_sigmas_commitment`.
func sigmasRange(c *types.CommonCircuitData) []uint64 {
	returnArr := make([]uint64, 0)
	for i := c.NumConstants; i <= c.NumConstants+c.Config.NumRoutedWires; i++ {
		returnArr = append(returnArr, i)
	}

	return returnArr
}

func numZSPartialProductsPolys(c *types.CommonCircuitData) uint64 {
	return c.Config.NumChallenges * (1 + c.NumPartialProducts)
}

func numQuotientPolys(c *types.CommonCircuitData) uint64 {
	return c.Config.NumChallenges * c.QuotientDegreeFactor
}

func PlaceHolderQueryRoundProofs(circuitData types.CommonCircuitData) []variables.FriQueryRound {
	numWires, friConfig, friParams := circuitData.Config.NumWires, circuitData.Config.FriConfig, circuitData.FriParams

	result := make([]variables.FriQueryRound, friParams.Config.NumQueryRounds)
	for i := range result {
		steps := make([]variables.FriQueryStep, len(friParams.ReductionArityBits))
		capHeight := friParams.Config.CapHeight
		codewordLenBits := friParams.LdeBits()
		for j := range steps {
			codewordLenBits -= int(friParams.ReductionArityBits[j])
			steps[j] = variables.NewFriQueryStep(friParams.ReductionArityBits[j], uint64(codewordLenBits)-capHeight)
		}

		result[i] = variables.FriQueryRound{
			InitialTreesProof: variables.NewFriInitialTreeProof([]variables.FriEvalProof{ // len equal to len(Oracles) = 4
				variables.NewFriEvalProof(make([]gl.Variable, numPreprocessedPolys(&circuitData)), variables.NewFriMerkleProof(friParams.DegreeBits+friConfig.RateBits-friConfig.CapHeight)),
				variables.NewFriEvalProof(make([]gl.Variable, numWires), variables.NewFriMerkleProof(friParams.DegreeBits+friConfig.RateBits-friConfig.CapHeight)),
				variables.NewFriEvalProof(make([]gl.Variable, numZSPartialProductsPolys(&circuitData)), variables.NewFriMerkleProof(friParams.DegreeBits+friConfig.RateBits-friConfig.CapHeight)),
				variables.NewFriEvalProof(make([]gl.Variable, numQuotientPolys(&circuitData)), variables.NewFriMerkleProof(friParams.DegreeBits+friConfig.RateBits-friConfig.CapHeight)),
			}),
			Steps: steps,
		}
	}
	return result
}

func PlaceHolderProof(circuitData types.CommonCircuitData) (variables.Proof, []gl.Variable) {
	return variables.Proof{
		WiresCap:                  variables.NewFriMerkleCap(circuitData.Config.FriConfig.CapHeight),
		PlonkZsPartialProductsCap: variables.NewFriMerkleCap(circuitData.Config.FriConfig.CapHeight),
		QuotientPolysCap:          variables.NewFriMerkleCap(circuitData.Config.FriConfig.CapHeight),
		Openings: variables.OpeningSet{
			Constants:       make([]gl.QuadraticExtensionVariable, circuitData.NumConstants), 			
			PlonkSigmas:     make([]gl.QuadraticExtensionVariable, circuitData.Config.NumRoutedWires),
			Wires:           make([]gl.QuadraticExtensionVariable, circuitData.Config.NumWires),
			PlonkZs:         make([]gl.QuadraticExtensionVariable, circuitData.Config.NumChallenges),
			PlonkZsNext:     make([]gl.QuadraticExtensionVariable, circuitData.Config.NumChallenges),
			PartialProducts: make([]gl.QuadraticExtensionVariable, circuitData.Config.NumChallenges*circuitData.NumPartialProducts),
			QuotientPolys:   make([]gl.QuadraticExtensionVariable, circuitData.Config.NumChallenges*circuitData.QuotientDegreeFactor),
		},
		OpeningProof: variables.FriProof{
			CommitPhaseMerkleCaps: PlaceHolderCommitPhaseMerkleCaps(circuitData.Config.FriConfig.CapHeight, len(circuitData.FriParams.ReductionArityBits)),
			QueryRoundProofs:      PlaceHolderQueryRoundProofs(circuitData),
			FinalPoly:             variables.NewPolynomialCoeffs(uint64(circuitData.FriParams.FinalPolyLen())),
			PowWitness:            gl.Variable{},
		},
	}, PlaceHolderPublicInputs(circuitData.NumPublicInputs)
}

// Returns the R1CS and the circuit digest that is going to be verified. It uses circuit data to generate a place holder proof.
func BuildCircuitPlaceHolder(commonCircuitDataPath, verifierCircuitDataPath string) (constraint.ConstraintSystem, string, error) {
	commonCircuitData := types.ReadCommonCircuitData(commonCircuitDataPath)
	verifierOnlyCircuitDataRaw := types.ReadVerifierOnlyCircuitData(verifierCircuitDataPath)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitDataRaw)
	proof, publicInputs := PlaceHolderProof(commonCircuitData)

	circuit := circuit.VerifierCircuit{
		Commitment:              frontend.Variable(0),
		PublicInputs:            publicInputs,
		Proof:                   proof,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	builder := scs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		return nil, "", fmt.Errorf("failed to compile circuit: %v", err)
	}

	return r1cs, verifierOnlyCircuitDataRaw.CircuitDigest, nil
}

// Returns the R1CS and the circuit digest that is going to be verified. It uses real proof to generate the place holder proof.
func BuildCircuit(commonCircuitDataPath, verifierCircuitDataPath, proofPath string) (constraint.ConstraintSystem, string, error) {
	commonCircuitData := types.ReadCommonCircuitData(commonCircuitDataPath)
	verifierOnlyCircuitDataRaw := types.ReadVerifierOnlyCircuitData(verifierCircuitDataPath)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitDataRaw)
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(proofPath))

	circuit := circuit.VerifierCircuit{
		Commitment:              frontend.Variable(0),
		PublicInputs:            proofWithPis.PublicInputs,
		Proof:                   proofWithPis.Proof,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	builder := scs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		return nil, "", fmt.Errorf("failed to compile circuit: %v", err)
	}

	return r1cs, verifierOnlyCircuitDataRaw.CircuitDigest, nil
}
