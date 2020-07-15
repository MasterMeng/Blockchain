package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

// IP define the Intellectual Property struct
type IP struct {
	Owner        string `json:"owner"`
	CreateTime   string `json:"createtime"`
	HashCode     string `json:"hashcode"`
	TransferTime string `json:"transfertime"`
}

// Init initializes the chaincode
func (ip *IP) Init(stub shim.ChaincodeStubInterface) peer.Response {
	fmt.Println("IP Chaincode Init")
	return shim.Success(nil)
}

// Invoke execute the chaincode function
func (ip *IP) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Error("Not find the function")
}

func (ip *IP) addIP(stub shim.ChaincodeStubInterface, argv []string) peer.Response {
	fmt.Println("Add an new IP")
	if len(argv) != 3 {
		return shim.Error("Incorrect number of arguments. Expecting 3")
	}

	resultByte, err := stub.GetState(argv[3])
	if err != nil {
		return shim.Error(err.Error())
	}

	if resultByte != nil {
		result := &IP{}
		err := json.Unmarshal(resultByte, result)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Error(fmt.Sprintf("%s owe the IP", result.Owner))
	}
	create := time.Now().String()
	res := &IP{
		Owner:        argv[1],
		CreateTime:   create,
		HashCode:     argv[2],
		TransferTime: create,
	}

	resByte, err := json.Marshal(res)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(argv[3], resByte)
	if err != nil {
		return shim.Error(fmt.Sprintf("Get some error: %s When putting IP information into the ledger", err.Error()))
	}
	return shim.Success([]byte("Put IP information Done"))
}

func (ip *IP) queryIP(stub shim.ChaincodeStubInterface, argv []string) peer.Response {
	fmt.Println("Query IP information")
	if len(argv) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}
	resultByte, err := stub.GetState(argv[1])
	if err != nil {
		return shim.Error(err.Error())
	}

	if resultByte == nil {
		return shim.Error(fmt.Sprintf("Not find the %s IP information", argv[1]))
	}
	return shim.Success(resultByte)
}

func (ip *IP) transferIP(stub shim.ChaincodeStubInterface, argv []string) peer.Response {
	fmt.Println("Transfer IP")
	if len(argv) != 4 {
		return shim.Error("Incorrect number of arguments. Expecting 4")
	}
	resultByte, err := stub.GetState(argv[2])
	if err != nil {
		return shim.Error(err.Error())
	}

	if resultByte == nil {
		return shim.Error(fmt.Sprintf("Not find the %s IP information", argv[2]))
	}

	result := &IP{}
	err = json.Unmarshal(resultByte, result)
	if err != nil {
		return shim.Error(err.Error())
	}

	if result.Owner != argv[1] {
		return shim.Error(fmt.Sprintf("%s is not owner of the %s", argv[1], argv[2]))
	}
	result.Owner = argv[3]
	result.TransferTime = time.Now().String()

	resultByte, err = json.Marshal(result)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(argv[3], resultByte)
	if err != nil {
		return shim.Error(fmt.Sprintf("Get some error: %s When putting IP information into the ledger", err.Error()))
	}
	return shim.Success([]byte(fmt.Sprintf("%s has been transferred to %s by %s", argv[2], argv[3], argv[1])))
}

func main() {
	err := shim.Start(new(IP))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}
