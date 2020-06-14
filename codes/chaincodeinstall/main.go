/*
This is an example for using fabric-sdk-go calling the fabcar chaincode in fabric-samples.
The fabric docker images and the fabric-samples used is v1.4.6.
Fabric-sdk-go is the latest.
*/

package main

import (
	"fmt"
	"os"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/cauthdsl"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	packager "github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

func installCC(org, user string, sdk *fabsdk.FabricSDK) (*resmgmt.Client, error) {
	client, err := msp.New(sdk.Context(), msp.WithOrg(org))

	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	userIdentigy, err := client.GetSigningIdentity(user)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	userclientcontent := sdk.Context(fabsdk.WithIdentity(userIdentigy))
	resclient, err := resmgmt.New(userclientcontent)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	// Packing the example cc from local
	// argv[0]: cc path in local
	// argv[1]: GOPATH
	ccPkg, err := packager.NewCCPackage("github.com/hyperledger/fabric-samples/chaincode/fabcar/go", "/home/m/go/")
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	ccreq := resmgmt.InstallCCRequest{
		Name:    "fabcar",
		Version: "1.0.0",
		Path:    "github.com/hyperledger/fabric-samples/chaincode/fabcar/go",
		Package: ccPkg,
	}
	responses, err := resclient.InstallCC(ccreq, resmgmt.WithRetry(retry.DefaultResMgmtOpts))
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	fmt.Println(responses)
	return resclient, nil
}

func main() {
	sdk, err := fabsdk.New(config.FromFile("./first-network.yaml"))
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	defer sdk.Close()

	fmt.Println("================= InstallCC start =================")
	// install chaincode
	// Using two orgs to endorse, so call installCC twice
	installCCResponse, _ := installCC("Org1", "Admin", sdk)
	installCC("Org2", "Admin", sdk)
	fmt.Println("================= InstallCC done =================")

	fmt.Println("================= InstantiateCC start =================")
	// Policy
	ccPolicy := cauthdsl.SignedByAnyMember([]string{"Org1MSP", "Org2MSP"})
	args := [][]byte{[]byte("init")}

	instantiateCCResponse, err := installCCResponse.InstantiateCC(
		"mychannel",
		resmgmt.InstantiateCCRequest{Name: "fabcar", Path: "github.com/hyperledger/fabric-samples/chaincode/fabcar/go", Version: "1.0.0", Policy: ccPolicy, Args: args},
		resmgmt.WithRetry(retry.DefaultResMgmtOpts))

	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	fmt.Println("TransactionID: ", instantiateCCResponse.TransactionID)
	fmt.Println("================= InstantiateCC done =================")

	fmt.Println("================= InvokeCC done =================")

	clientChannelContext := sdk.ChannelContext("mychannel", fabsdk.WithUser("Admin"))

	channalClient, err := channel.New(clientChannelContext)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	// call the initLedger function
	_, err = channalClient.Execute(channel.Request{ChaincodeID: "fabcar", Fcn: "initLedger", Args: nil}, channel.WithRetry(retry.DefaultChannelOpts))

	// call the createCar function
	createCarArgs := [][]byte{[]byte("CAR20"), []byte("Toyota"), []byte("Prius"), []byte("red"), []byte("Jsonca")}
	resp1, err := channalClient.Execute(channel.Request{ChaincodeID: "fabcar", Fcn: "createCar", Args: createCarArgs}, channel.WithRetry(retry.DefaultChannelOpts))
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	fmt.Println(resp1.TransactionID)

	// call the queryAllCars function
	resp2, err := channalClient.Execute(channel.Request{ChaincodeID: "fabcar", Fcn: "queryAllCars", Args: nil}, channel.WithRetry(retry.DefaultChannelOpts))
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	fmt.Println(string(resp2.Payload))
	fmt.Println("================= InvokeCC done =================")
}
