// payment project main.go
package main

import (
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
)

type PaymentChaincode struct {
}

func (t *PaymentChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	_, args := stub.GetFunctionAndParameters()
	if len(args) != 4 {
		return shim.Error("初始化时必须指定两个用户并指定相应的初始余额")
	}

	var a = args[0]
	var avalStr = args[1]
	var b = args[2]
	var bvalStr = args[3]

	if len(a) < 2 {
		return shim.Error(a + " 用户名长度不能少于2个字符长度")
	}
	if len(b) < 2 {
		return shim.Error(b + " 用户名长度不能少于2个字符长度")
	}

	_, err := strconv.Atoi(avalStr)
	if err != nil {
		return shim.Error("指定账户的初始余额错误：" + avalStr)
	}
	_, err = strconv.Atoi(bvalStr)
	if err != nil {
		return shim.Error("指定账户的初始余额错误：" + bvalStr)
	}

	err = stub.PutState(a, []byte(avalStr))
	if err != nil {
		return shim.Error(a + " 保存状态时发生错误")
	}
	err = stub.PutState(b, []byte(bvalStr))
	if err != nil {
		return shim.Error(b + " 保存状态时发生错误")
	}
	return shim.Success([]byte("初始化成功"))
}

func (t *PaymentChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	fun, args := stub.GetFunctionAndParameters()
	if fun == "find" {
		return find(stub, args)
	} else if fun == "payment" {
		return payment(stub, args)
	} else if fun == "del" {
		return delAccount(stub, args)
	} else if fun == "add" {
		return t.addAccount(stub, args)
	} else if fun == "set" {
		return t.set(stub, args)
	} else if fun == "get" {
		return t.get(stub, args)
	}
	return shim.Error("非法操作")

}

func find(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 1 {
		return shim.Error("必须且只能指定要查询的用户名")
	}

	result, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error("查询 " + args[0] + " 账户信息失败：" + err.Error())
	}
	if result == nil {
		return shim.Error("账户 " + args[0] + "没有查到余额信息")
	}
	return shim.Success(result)
}

func payment(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 3 {
		return shim.Error("必须且只能指定源账户、目标账户以及转账金额")
	}

	source := args[0]
	target := args[1]
	x := args[2]

	svalStr, err := stub.GetState(source)
	if err != nil {
		return shim.Error("查询" + source + "账户失败")
	}

	tvalStr, err := stub.GetState(target)
	if err != nil {
		return shim.Error("查询" + target + "账户失败")
	}

	//转账
	xval, err := strconv.Atoi(x)
	if err != nil {
		return shim.Error("转账金额错误")
	}

	sval, err := strconv.Atoi(string(svalStr))
	if err != nil {
		return shim.Error("处理源账户余额时发生错误")
	}
	tval, err := strconv.Atoi(string(tvalStr))
	if err != nil {
		return shim.Error("处理目标账户余额时发生错误")
	}

	if xval > sval {
		return shim.Error("目标账户余额不足，交易失败")
	}

	sval = sval - xval
	tval = tval + xval

	//记账
	err = stub.PutState(source, []byte(strconv.Itoa(sval)))
	if err != nil {
		return shim.Error("保存转账后源账户信息失败")
	}
	err = stub.PutState(target, []byte(strconv.Itoa(tval)))
	if err != nil {
		return shim.Error("保存转账后目标账户信息失败")
	}
	return shim.Success([]byte("转账成功"))
}

func delAccount(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 1 {
		return shim.Error("必须且只能指定要删除的账户名称")
	}
	result, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error("查询 " + args[0] + " 账户信息失败" + err.Error())
	}
	if result == nil {
		return shim.Error("根据指定 " + args[0] + " 没有查询到对应的余额")
	}
	err = stub.DelState(args[0])
	if err != nil {
		return shim.Error("删除指定的账户失败: " + args[0] + ", " + err.Error())
	}
	return shim.Success([]byte("删除指定的账户成功" + args[0]))
}

func (t *PaymentChaincode) addAccount(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 2 {
		return shim.Error("必须且只能指定要新增的账户及初始金额")
	}

	a := args[0]
	val := args[1]

	if len(a) < 2 {
		return shim.Error(a + " 用户名长度不能少于2个字符长度")
	}
	_, err := strconv.Atoi(val)
	if err != nil {
		return shim.Error("指定账户的初始余额错误：" + val)
	}

	result, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error("查询 " + args[0] + " 账户信息失败" + err.Error())
	}
	if result == nil {
		err = stub.PutState(args[0], []byte(args[1]))
		if err != nil {
			return shim.Error("保存账户：" + a + " 时发生错误")
		}
		return shim.Success([]byte("新增账户成功"))
	}
	return t.set(stub, args)
}

func (t *PaymentChaincode) set(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 2 {
		return shim.Error("必须且只能指定账户名和存入的金额")
	}

	result, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error("查询指定账户信息失败")
	}
	if result == nil {
		return shim.Error("指定账户不存在")
	}

	val, err := strconv.Atoi(string(result))
	if err != nil {
		return shim.Error("处理账户余额时发生错误")
	}

	x, err := strconv.Atoi(args[1])
	if err != nil {
		return shim.Error("处理账户转入金额时发生错误")
	}

	val = val + x
	err = stub.PutState(args[0], []byte(strconv.Itoa(val)))
	if err != nil {
		return shim.Error("存入金额时发生错误")
	}
	return shim.Success([]byte("存入操作成功"))
}

func (t *PaymentChaincode) get(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 2 {
		return shim.Error("必须且只能指定要查询的账户及要提取的金额")
	}

	x, err := strconv.Atoi(args[1])
	if err != nil {
		return shim.Error("提取金额输入有误")
	}

	result, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error("查询指定账户余额时发生错误")
	}
	if result == nil {
		return shim.Error("指定账户不存在或已注销")
	}

	val, err := strconv.Atoi(string(result))
	if err != nil {
		return shim.Error("处理账户余额时发生错误")
	}
	if val < x {
		return shim.Error("账户余额不足，无法提取")
	}

	val = val - x
	err = stub.PutState(args[0], []byte(strconv.Itoa(val)))
	if err != nil {
		return shim.Error("提取失败，保存余额信息时发生错误")
	}
	return shim.Success([]byte("提取成功"))
}

func main() {
	err := shim.Start(new(PaymentChaincode))
	if err != nil {
		fmt.Println("启动 Payment 链码时发生错误：%s", err)
	}
}
