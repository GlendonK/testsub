package main

/*
	This file contains the chaincode with the implementation of ps signature, ecdsa with zk proof.
*/
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}

func (s *SmartContract) CheckClient(ctx contractapi.TransactionContextInterface) string {

	// stub := ctx.GetStub()
	id, _ := ctx.GetClientIdentity().GetID()
	mspID, _ := ctx.GetClientIdentity().GetMSPID()
	// attr, _, _ := ctx.GetClientIdentity().GetAttributeValue("lol")

	return ("id: " + id + "mspId: " + mspID)
}

func (s *SmartContract) CreateRedactable(ctx contractapi.TransactionContextInterface, id string, jsonString string) error {

	exists, err := s.DIDExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the did %s already exists", id)
	}

	var c map[string]interface{}
	json.Unmarshal([]byte(jsonString), &c)

	cp, _ := json.Marshal(c["proof"])
	cs, _ := json.Marshal(c["CredentialSubject"])

	var sub map[string]string
	json.Unmarshal(cs, &sub)
	msg := sub["message"]

	var p []map[string]string
	json.Unmarshal(cp, &p)

	psb64 := p[0]["signature"]
	// rb64 := p[1]["signature"]

	var ps map[string]string
	psSig, _ := base64.StdEncoding.DecodeString(psb64)
	json.Unmarshal(psSig, &ps)

	signature1 := ps["signature1"]
	signature2 := ps["signature2"]

	var message []string
	message = append(message, msg)

	redactableJSON, _ := json.Marshal(c)

	err = VerifyRedactable(message, signature1, signature2)

	if err == nil {
		return ctx.GetStub().PutState(id, redactableJSON)
	} else {
		return err
	}

}

func (s *SmartContract) CreateRedactableDerive(ctx contractapi.TransactionContextInterface, id string, jsonString string) error {

	exists, err := s.DIDExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the did %s already exists", id)
	}

	var c map[string]interface{}
	json.Unmarshal([]byte(jsonString), &c)

	cp, _ := json.Marshal(c["proof"])
	cs, _ := json.Marshal(c["CredentialSubject"])

	var sub map[string]string
	json.Unmarshal(cs, &sub)
	sid := sub["id"]
	givenName := sub["givenName"]
	familyName := sub["familyName"]
	birthDate := sub["birthDate"]

	var p []map[string]string
	json.Unmarshal(cp, &p)

	psb64 := p[0]["signature"]
	rb64 := p[1]["signature"]

	var ps map[string]string
	psSig, _ := base64.StdEncoding.DecodeString(psb64)
	json.Unmarshal(psSig, &ps)

	// signature1 := ps["signature1"]
	// signature2 := ps["signature2"]

	var r map[string]string
	rSig, _ := base64.StdEncoding.DecodeString(rb64)
	json.Unmarshal(rSig, &r)

	sigma1D := r["sigma1D"]
	sigma2D := r["sigma2D"]
	sigma3D := r["sigma3D"]
	sigmaD := r["sigmaD"]

	var message []string
	message = append(message, sid)
	message = append(message, givenName)
	message = append(message, familyName)
	message = append(message, birthDate)

	err = VerifiyRedactableDerive(message, sigma1D, sigma2D, sigma3D, sigmaD)

	redactableJSON, _ := json.Marshal(c)

	if err == nil {
		return ctx.GetStub().PutState(id, redactableJSON)
	} else {
		return fmt.Errorf("PutState: err")
	}

}

func (s *SmartContract) ReadRedactable(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	redactable, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err).Error(), nil
	}
	if redactable == nil {
		return fmt.Errorf("the asset %s does not exist", id).Error(), nil
	}

	var c map[string]interface{}
	json.Unmarshal(redactable, &c)

	cp, _ := json.Marshal(c["proof"])
	cs, _ := json.Marshal(c["CredentialSubject"])

	var sub map[string]string
	json.Unmarshal(cs, &sub)
	msg := sub["message"]

	var p []map[string]string
	json.Unmarshal(cp, &p)

	psb64 := p[0]["signature"]
	// rb64 := p[1]["signature"]

	var ps map[string]string
	psSig, _ := base64.StdEncoding.DecodeString(psb64)
	json.Unmarshal(psSig, &ps)

	signature1 := ps["signature1"]
	signature2 := ps["signature2"]

	var message []string
	message = append(message, msg)

	err = VerifyRedactable(message, signature1, signature2)

	if err != nil {

		panic("VerifyRedactable: error")
	}
	return string(redactable), nil

}

func (s *SmartContract) ReadRedactableDerive(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	redactableDerive, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err).Error(), nil
	}
	if redactableDerive == nil {
		return fmt.Errorf("the asset %s does not exist", id).Error(), nil
	}

	var c map[string]interface{}
	json.Unmarshal(redactableDerive, &c)

	cp, _ := json.Marshal(c["proof"])
	cs, _ := json.Marshal(c["CredentialSubject"])

	var sub map[string]string
	json.Unmarshal(cs, &sub)
	sid := sub["id"]
	givenName := sub["givenName"]
	familyName := sub["familyName"]
	birthDate := sub["birthDate"]

	var p []map[string]string
	json.Unmarshal(cp, &p)

	psb64 := p[0]["signature"]
	rb64 := p[1]["signature"]

	var ps map[string]string
	psSig, _ := base64.StdEncoding.DecodeString(psb64)
	json.Unmarshal(psSig, &ps)

	// signature1 := ps["signature1"]
	// signature2 := ps["signature2"]

	var r map[string]string
	rSig, _ := base64.StdEncoding.DecodeString(rb64)
	json.Unmarshal(rSig, &r)

	sigma1D := r["sigma1D"]
	sigma2D := r["sigma2D"]
	sigma3D := r["sigma3D"]
	sigmaD := r["sigmaD"]

	var message []string
	message = append(message, sid)
	message = append(message, givenName)
	message = append(message, familyName)
	message = append(message, birthDate)

	// err = VerifiyRedactableDerive(message, sigJson.Sigma1D, sigJson.Sigma2D, sigJson.Sigma3D, sigJson.SigmaD)

	err = VerifiyRedactableDerive(message, sigma1D, sigma2D, sigma3D, sigmaD)

	if err != nil {

		panic("VerifyRedactable: error")
	}
	return string(redactableDerive), nil

}

/*
	Create Document for Ps Signature.
*/
func (s *SmartContract) CreatePsSignature(ctx contractapi.TransactionContextInterface, id string, jsonString string) error {
	exists, err := s.DIDExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the did %s already exists", id)
	}

	// pubX := "000be0b4b379bf94d9f7efb948e46b4e8dc7652a66614b4e2ce97686cf0effa250088f177812c06e1f4eeac8452a99170e3c6da36e39a0ed921ca396e8c860066f524db59dbf927a75311214445fb213d721eba7b74126d180a12c112d240fff4ae135c11e904660b892c5b732bda30f458e7cbd69b51212644429a6beb91ff8"
	// pubY := "07d36ed76f685ff8cb12b3ef09b903adb044993b33a97ea9ea9c72d55f02098a5ca9c21ffb8ca8ed4cb117977257840e69bbb66f14b8a8298404d880186770815ed3e2adbd66e6e0e11d7817833777040d818d2058de1f1b16fa4edc36e6eda26e7329ade890a21f98b0df91a47e0d725810616af4479310ab7af803855d7f89"
	// // var didDoc DID
	// // json.Unmarshal(didJSON, &didDoc)
	// // dd, _ := json.Marshal(did.Document)
	// // msg := hex.EncodeToString(dd)
	// msg := "hello"
	// sigX := "28027ea534cc91da7cdbba8d0cb068fff50988b7e5821bf589cd8c6386709e0e68f14d8af4250796ef29a5634ff99ff3c62a3975099b2d81197e351f95bedf70"
	// sigY := "27b657305bac43852e97a4d7126e78d9ee8ff25fc0a0199ce5639c47227848498c5f633b5aad538658d60662922ad274cbdeb1ec68d56a888641c67fdf285cd9"

	var c map[string]interface{}
	json.Unmarshal([]byte(jsonString), &c)

	cp, _ := json.Marshal(c["proof"])
	cs, _ := json.Marshal(c["CredentialSubject"])

	var sub map[string]string
	json.Unmarshal(cs, &sub)
	message := sub["message"]

	var p []map[string]string
	json.Unmarshal(cp, &p)

	psb64 := p[0]["signature"]
	// rb64 := p[1]["signature"]

	var ps map[string]string
	psSig, _ := base64.StdEncoding.DecodeString(psb64)
	json.Unmarshal(psSig, &ps)

	signatureX := ps["signatureX"]
	signatureY := ps["signatureY"]
	pubX := ps["pubX"]
	pubY := ps["pubY"]

	valid := VerifyPS(pubX, pubY, message, signatureX, signatureY)

	didJSON, err := json.Marshal(c)
	if err != nil {
		return err
	}

	// valid, _, hash := Verify(didJSON)

	if valid == nil {
		return ctx.GetStub().PutState(id, didJSON)
	} else {
		return fmt.Errorf("not valid")
	}

}

/*
	Read method for documents signed with PS Signaure.
*/
func (s *SmartContract) ReadPsSignature(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	didJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err).Error(), nil
	}
	if didJSON == nil {
		return fmt.Errorf("the asset %s does not exist", id).Error(), nil
	}

	var c map[string]interface{}
	json.Unmarshal(didJSON, &c)

	cp, _ := json.Marshal(c["proof"])
	cs, _ := json.Marshal(c["CredentialSubject"])

	var sub map[string]string
	json.Unmarshal(cs, &sub)
	message := sub["message"]

	var p []map[string]string
	json.Unmarshal(cp, &p)

	psb64 := p[0]["signature"]
	// rb64 := p[1]["signature"]

	var ps map[string]string
	psSig, _ := base64.StdEncoding.DecodeString(psb64)
	json.Unmarshal(psSig, &ps)

	signatureX := ps["signatureX"]
	signatureY := ps["signatureY"]
	pubX := ps["pubX"]
	pubY := ps["pubY"]

	valid := VerifyPS(pubX, pubY, message, signatureX, signatureY)

	if valid == nil {
		return string(didJSON), nil
	} else {

		return "not valid", valid
	}

}

/*
	create document for ecdsa.
*/
func (s *SmartContract) CreateDID(ctx contractapi.TransactionContextInterface, id string, jsonString string) error {
	exists, err := s.DIDExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the did %s already exists", id)
	}

	var c map[string]interface{}
	json.Unmarshal([]byte(jsonString), &c)

	cp, _ := json.Marshal(c["proof"])
	cs, _ := json.Marshal(c["CredentialSubject"])

	var sub map[string]string
	json.Unmarshal(cs, &sub)
	message := sub["message"]

	var p []map[string]string
	json.Unmarshal(cp, &p)

	psb64 := p[0]["signature"]
	// rb64 := p[1]["signature"]

	var ps map[string]string
	psSig, _ := base64.StdEncoding.DecodeString(psb64)
	json.Unmarshal(psSig, &ps)

	sig := ps["sig"]
	hash := ps["hash"]
	pubX := ps["pubX"]
	pubY := ps["pubY"]

	didJSON, err := json.Marshal(c)
	if err != nil {
		return err
	}

	valid := Verify(message, pubX, pubY, sig, hash)

	// if ps != nil {
	// 	panic("ps err not nil")
	// }

	if valid {
		return ctx.GetStub().PutState(id, didJSON)
	} else {
		return fmt.Errorf("not valid")
	}

}

/*
	Read method for documetns signed with ecdsa.
*/
func (s *SmartContract) ReadDID(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	didJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err).Error(), nil
	}
	if didJSON == nil {
		return fmt.Errorf("the asset %s does not exist", id).Error(), nil
	}

	var c map[string]interface{}
	json.Unmarshal(didJSON, &c)

	cp, _ := json.Marshal(c["proof"])
	cs, _ := json.Marshal(c["CredentialSubject"])

	var sub map[string]string
	json.Unmarshal(cs, &sub)
	message := sub["message"]

	var p []map[string]string
	json.Unmarshal(cp, &p)

	psb64 := p[0]["signature"]
	// rb64 := p[1]["signature"]

	var ps map[string]string
	psSig, _ := base64.StdEncoding.DecodeString(psb64)
	json.Unmarshal(psSig, &ps)

	sig := ps["sig"]
	hash := ps["hash"]
	pubX := ps["pubX"]
	pubY := ps["pubY"]

	valid := Verify(message, pubX, pubY, sig, hash)

	if valid {
		return string(didJSON), nil
	} else {

		return "not valid else", nil

	}

}

func (s *SmartContract) DIDExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return assetJSON != nil, nil
}

/*
	Update example for ecdsa.
*/
func (s *SmartContract) UpdateDID(ctx contractapi.TransactionContextInterface, id string, jsonString string) error {
	exists, err := s.DIDExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the did %s does not exist", id)
	}

	var c map[string]interface{}
	json.Unmarshal([]byte(jsonString), &c)

	cp, _ := json.Marshal(c["proof"])
	cs, _ := json.Marshal(c["CredentialSubject"])

	var sub map[string]string
	json.Unmarshal(cs, &sub)
	message := sub["message"]

	var p []map[string]string
	json.Unmarshal(cp, &p)

	psb64 := p[0]["signature"]
	// rb64 := p[1]["signature"]

	var ps map[string]string
	psSig, _ := base64.StdEncoding.DecodeString(psb64)
	json.Unmarshal(psSig, &ps)

	sig := ps["sig"]
	hash := ps["hash"]
	pubX := ps["pubX"]
	pubY := ps["pubY"]

	didJSON, err := json.Marshal(c)
	if err != nil {
		return err
	}

	valid := Verify(message, pubX, pubY, sig, hash)

	// if ps != nil {
	// 	panic("ps err not nil")
	// }

	if valid {
		return ctx.GetStub().PutState(id, didJSON)
	} else {
		return fmt.Errorf("not valid")
	}
}

func (s *SmartContract) DeleteDID(ctx contractapi.TransactionContextInterface, id string) error {
	exists, err := s.DIDExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the did %s does not exist", id)
	}

	return ctx.GetStub().DelState(id)
}

func main() {
	assetChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating own chaincode: %v", err)
	}

	if err := assetChaincode.Start(); err != nil {
		log.Panicf("Error starting own chaincode: %v", err)
	}
}
