// testcdb project main.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
)

type CouchChaincode struct {
}

type CarInfo struct {
	ObjectType string `json:"docType"`
	CarID      string `json:"carid"`
	Owner      string `json:"owner"`
	Brand      string `json:"brand"`
	CarName    string `json:"carname"`
	Price      string `json:"price"`
}

func (t *CouchChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success([]byte("Chaincode Init Successfully"))
}

func (t *CouchChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	funs, args := stub.GetFunctionAndParameters()
	if funs == "addCars" {
		return addCars(stub, args)
	} else if funs == "queryCars" {
		return queryCars(stub, args)
	} else if funs == "modifyCars" {
		return modifyCars(stub, args)
	} else if funs == "deleteCars" {
		return deleteCars(stub, args)
	}
	return shim.Error("Invalid Operation: Not find the function name")
}

func addCars(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 5 {
		return shim.Error("Incorrect number of arguments. Expecting 5")
	}

	car := CarInfo{
		ObjectType: "carInfo",
		CarID:      args[0],
		Owner:      args[1],
		Brand:      args[2],
		CarName:    args[3],
		Price:      args[4],
	}

	carByte, _ := json.Marshal(car)
	err := stub.PutState(car.CarID, carByte)
	if err != nil {
		return shim.Error("Add CarInfo unsuccessfully")
	}
	return shim.Success([]byte("Add CarInfo successfully"))
}

func queryCars(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	queryString := args[0]

	result, err := getCarsByQueryString(stub, queryString)
	if err != nil {
		return shim.Error("Query information error: " + err.Error())
	}

	return shim.Success(result)
}

func modifyCars(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 5 {
		return shim.Error("Incorrect number of arguments. Expecting 5")
	}

	car := CarInfo{
		ObjectType: "carInfo",
		CarID:      args[0],
		Owner:      args[1],
		Brand:      args[2],
		CarName:    args[3],
		Price:      args[4],
	}

	carByte, _ := json.Marshal(car)
	err := stub.PutState(car.CarID, carByte)
	if err != nil {
		return shim.Error("Modify CarInfo unsuccessfully")
	}
	return shim.Success([]byte("Modify CarInfo successfully"))

}

func deleteCars(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting ")
	}

	result, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error("query " + args[0] + " Info error: " + err.Error())
	}
	if result == nil {
		return shim.Error(args[0] + "has deleted")
	}
	err = stub.DelState(args[0])
	if err != nil {
		return shim.Error(args[0] + "delete unsuccessfully")
	}

	return shim.Success([]byte(args[0] + "delete successfully"))
}

func getCarsByQueryString(stub shim.ChaincodeStubInterface, queryString string) ([]byte, error) {
	iter, err := stub.GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var buffer bytes.Buffer
	var isSplit bool
	for iter.HasNext() {
		result, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if isSplit {
			buffer.WriteString("; ")
		}
		buffer.WriteString("Key: ")
		buffer.WriteString(result.Key)
		buffer.WriteString(" Value: ")
		buffer.WriteString(string(result.Value))

		isSplit = true
	}
	return buffer.Bytes(), nil
}

func main() {
	err := shim.Start(new(CouchChaincode))
	if err != nil {
		fmt.Errorf("Chaincode Statr error: %v", err)
	}
}
