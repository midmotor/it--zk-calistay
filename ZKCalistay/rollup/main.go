package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

/*
Public tag:
`gnark:",public"`
*/

// Account, transfer, curcuit

// verify: sign, , merkleproof roothash check
const (
	depth = 5
)

type Account struct {
	Nonce   frontend.Variable
	Balance frontend.Variable
	Index   frontend.Variable
	PubKey  eddsa.PublicKey
}

type Transfer struct {
	Amount         frontend.Variable
	Nonce          frontend.Variable
	SenderPubKey   eddsa.PublicKey
	ReceiverPubKey eddsa.PublicKey
	Signature      eddsa.Signature
}

type Circuit struct {
	SenderAccountBefore  Account
	ReciverAccountBefore Account

	SenderAccountAfter  Account
	ReciverAccountAfter Account

	Transfer Transfer

	MerkleProofReceiverBefore merkle.MerkleProof
	MerkleProofReceiverAfter  merkle.MerkleProof

	MerkleProofSenderBefore merkle.MerkleProof
	MerkleProofSenderAfter  merkle.MerkleProof

	IndexReceiver frontend.Variable
	IndexSender   frontend.Variable
	///

	RootHashBefore frontend.Variable `gnark:",public"`
	RootHashAfter  frontend.Variable `gnark:",public"`
}

func verifyUpdated(api frontend.API, from, to, fromUpdated, toUpdated Account, amount frontend.Variable) {

	nonceUpdated := api.Add(from.Nonce, 1)
	api.AssertIsEqual(nonceUpdated, fromUpdated.Nonce)

	api.AssertIsLessOrEqual(amount, from.Balance)

	// for sender
	newFromBalanced := api.Sub(from.Balance, amount)
	api.AssertIsEqual(newFromBalanced, fromUpdated.Balance)

	// for receiver

	newToBalanced := api.Add(to.Balance, amount)
	api.AssertIsEqual(newToBalanced, toUpdated.Balance)

	api.AssertIsEqual(from.PubKey.A.X, fromUpdated.PubKey.A.X)
	api.AssertIsEqual(from.PubKey.A.Y, fromUpdated.PubKey.A.Y)

	api.AssertIsEqual(to.PubKey.A.X, toUpdated.PubKey.A.X)
	api.AssertIsEqual(to.PubKey.A.Y, toUpdated.PubKey.A.Y)
}

func verifySignature(api frontend.API, t Transfer, hFunc mimc.MiMC) error {

	hFunc.Reset()

	hFunc.Write(t.Nonce, t.Amount, t.SenderPubKey.A.X, t.SenderPubKey.A.Y, t.ReceiverPubKey.A.X, t.ReceiverPubKey.A.Y)

	hTransfer := hFunc.Sum()

	curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254)

	err := eddsa.Verify(curve, t.Signature, hTransfer, t.SenderPubKey, &hFunc)

	if err != nil {
		return err
	}

	return nil

}

func (circuit *Circuit) Define(api frontend.API) error {

	verifyUpdated(api, circuit.SenderAccountBefore, circuit.ReciverAccountBefore, circuit.SenderAccountAfter, circuit.ReciverAccountAfter, circuit.Transfer.Amount)

	hFunc, _ := mimc.NewMiMC(api)
	verifySignature(api, circuit.Transfer, hFunc)

	api.AssertIsEqual(circuit.RootHashBefore, circuit.MerkleProofReceiverBefore.RootHash)
	api.AssertIsEqual(circuit.RootHashBefore, circuit.MerkleProofSenderBefore.RootHash)
	api.AssertIsEqual(circuit.RootHashAfter, circuit.MerkleProofReceiverAfter.RootHash)
	api.AssertIsEqual(circuit.RootHashAfter, circuit.MerkleProofSenderAfter.RootHash)

	// the leafs of the Merkle proofs must match the index of the accounts
	api.AssertIsEqual(circuit.ReciverAccountBefore.Index, circuit.IndexReceiver)
	api.AssertIsEqual(circuit.ReciverAccountBefore.Index, circuit.IndexReceiver)
	api.AssertIsEqual(circuit.SenderAccountBefore.Index, circuit.IndexSender)
	api.AssertIsEqual(circuit.SenderAccountAfter.Index, circuit.IndexSender)

	// verify the inclusion proofs
	circuit.MerkleProofReceiverBefore.VerifyProof(api, &hFunc, circuit.IndexReceiver)
	circuit.MerkleProofSenderBefore.VerifyProof(api, &hFunc, circuit.IndexSender)
	circuit.MerkleProofReceiverAfter.VerifyProof(api, &hFunc, circuit.IndexReceiver)
	circuit.MerkleProofSenderAfter.VerifyProof(api, &hFunc, circuit.IndexSender)

	return nil
}

func main() {

	var rollup Circuit

	rollup.MerkleProofReceiverBefore.Path = make([]frontend.Variable, depth)
	rollup.MerkleProofReceiverAfter.Path = make([]frontend.Variable, depth)
	rollup.MerkleProofSenderBefore.Path = make([]frontend.Variable, depth)
	rollup.MerkleProofSenderAfter.Path = make([]frontend.Variable, depth)

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &rollup)

	if err != nil {
		fmt.Printf("\"r1cs üretilirken hata oluştu\": %v\n", err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	_ = vk

	if err != nil {
		fmt.Printf("\"pk ve vk üretilirken hata oluştu\": %v\n", err)
	}

	fmt.Printf("pk.NbG1(): %v\n", pk.NbG1())

	fmt.Printf("pk.NbG2(): %v\n", pk.NbG2())
}
