// testcdb project main.go
package main

import (
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
	Price      int    `json:"price"`
}

func (t *CouchChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success([]byte(string("链码初始化成功")))
}

func (t *CouchChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	funs, args := shim.GetFunctionAndParameters()
	if funs == "addCars" {
		return addCars(stub, args)
	} else if funs == "queryCars" {
		return queryCars(stub, args)
	} else if funs == "modifyCars" {
		return modifyCars(stub, args)
	} else if funs == "deleteCars" {
		return deleteCars(stub, args)
	}
	return shim.Error("无效操作：指定函数未定义")
}

func addCars(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 5 {
		return shim.Error("传入参数个数错误！")
	}

	car := CarInfo{
		ObjectType: "carInfo",
		CarID:      args[0],
		Owner:      args[1],
		Brand:      args[2],
		CarName:    args[3],
		Price:      int(args[4]),
	}

	carByte, _ := json.Marshal(car)
	err := stub.PutState(car.CarID, carByte)
	if err != nil {
		return shim.Error("新增汽车信息失败！")
	}
	return shim.Success([]byte(string("新增汽车信息成功。。。")))
}

func queryCars(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	return shim.Success(nil)
}

func modifyCars(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	return shim.Success(nil)
}

func deleteCars(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	return shim.Success(nil)
}

func main() {
	err := shim.Start(new(CouchChaincode))
	if err != nil {
		fmt.Errorf("链码启动失败：%v", err)
	}
}
