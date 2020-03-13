# Fabric-ca client端初始化过程源码分析  

本文从Fabric-ca源码入手，简单分析client启动时的过程。Fabric-ca源码可以从[github.com](https://github.com/hyperledger/fabric-ca/releases)下载，本文以**v1.4.6**为例进行简单分析。  

与server相似，本文也是从**main.go**开始：  

```go  
// fabric-ca/cmd/fabric-ca-client/main.go

package main

import (
	...
)

// The fabric-ca client main
func main() {
	if err := command.RunMain(os.Args); err != nil {
		os.Exit(1)
	}
}
```  

`main()`函数只是调用了`package command`中的`RunMain()`函数，所以接下来我们以`RunMain()`函数为起点来简析client端的启动过程，其中包括client端的初始化以及跟server端的初次交互：  

```go  
// fabric-ca/cmd/fabric-ca-client/command/root.go  

package command

import "os"

// RunMain is the fabric-ca client main
func RunMain(args []string) error {
	// Save the os.Args
	saveOsArgs := os.Args
	os.Args = args

	// Execute the command
	cmdName := ""
	if len(args) > 1 {
		cmdName = args[1]
	}
	ccmd := NewCommand(cmdName)
	err := ccmd.Execute()

	// Restore original os.Args
	os.Args = saveOsArgs

	return err
}
```  

不难看出，与server类似，都是先通过`NewCommand()`函数来添加命令，之后再通过`Execute()`来执行操作：  

```go  
// fabric-ca/cmd/fabric-ca-client/command/clientcmd.go

// ClientCmd encapsulates cobra command that provides command line interface
// for the Fabric CA client and the configuration used by the Fabric CA client
type ClientCmd struct {
	// name of the sub command
	name string
	// rootCmd is the base command for the Hyerledger Fabric CA client
	rootCmd *cobra.Command
	// My viper instance
	myViper *viper.Viper
	// cfgFileName is the name of the configuration file
	cfgFileName string
	// homeDirectory is the location of the client's home directory
	homeDirectory string
	// clientCfg is the client's configuration
	clientCfg *lib.ClientConfig
	// cfgAttrs are the attributes specified via flags or env variables
	// and translated to Attributes field in registration
	cfgAttrs []string
	// cfgAttrReqs are the attribute requests specified via flags or env variables
	// and translated to the AttrReqs field in enrollment
	cfgAttrReqs []string
	// cfgCsrNames are the certificate signing request names specified via flags
	// or env variables
	cfgCsrNames []string
	// csrCommonName is the certificate signing request common name specified via the flag
	csrCommonName string
	// gencrl command argument values
	crlParams crlArgs
	// revoke command argument values
	revokeParams revokeArgs
	// profileMode is the profiling mode, cpu or mem or empty
	profileMode string
	// profileInst is the profiling instance object
	profileInst interface {
		Stop()
	}
	// Dynamically configuring identities
	dynamicIdentity identityArgs
	// Dynamically configuring affiliations
	dynamicAffiliation affiliationArgs
	// Set to log level
	logLevel string
}

// NewCommand returns new ClientCmd ready for running
func NewCommand(name string) *ClientCmd {
	c := &ClientCmd{
		myViper: viper.New(),
	}
	c.name = strings.ToLower(name)
	c.init()
	return c
}

...

// init initializes the ClientCmd instance
// It intializes the cobra root and sub commands and
// registers command flgs with viper
func (c *ClientCmd) init() {
	...

	c.rootCmd.AddCommand(c.newRegisterCommand(),
		newEnrollCmd(c).getCommand(),
		c.newReenrollCommand(),
		c.newRevokeCommand(),
		newGetCAInfoCmd(c).getCommand(),
		c.newGenCsrCommand(),
		c.newGenCRLCommand(),
		c.newIdentityCommand(),
		c.newAffiliationCommand(),
		createCertificateCommand(c))
	c.rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Prints Fabric CA Client version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(metadata.GetVersionInfo(cmdName))
		},
	})
	c.registerFlags()
	...
}
```  

在`NewCommand()`函数中，创建了一个`*ClientCmd`的对象，之后，调用该对象的`init()`方法。在`init()`方法中，首先实例化了`*ClientCmd.rootCmd`，其中会要执行`checkAndEnableProfiling()`来检查运行环境：  

```go  
// checkAndEnableProfiling checks for the FABRIC_CA_CLIENT_PROFILE_MODE
// env variable, if it is set to "cpu", cpu profiling is enbled;
// if it is set to "heap", heap profiling is enabled
func (c *ClientCmd) checkAndEnableProfiling() error {
	...
}

// registerFlags registers command flags with viper
func (c *ClientCmd) registerFlags() {
	...
}
```  

之后会调用`AddCommand()`函数来添加`newRegisterCommand()`、`newEnrollCmd(c).getCommand()`、`newReenrollCommand()`、`newRevokeCommand()`、`newGetCAInfoCmd(c).getCommand()`、`newGenCsrCommand()`、`newGenCRLCommand()`、`newIdentityCommand()`、`newAffiliationCommand()`、`createCertificateCommand()`和获取client版本的命令。随后执行`c.registerFlags()`操作。`registerFlags()`函数中主要是注册一些命令行参数，这里就不细究了。  

## newRegisterCommand()  

```go  
// fabric-ca/cmd/fabric-ca-client/command/register.go

func (c *ClientCmd) newRegisterCommand() *cobra.Command {
	...
}

// The client register main logic
func (c *ClientCmd) runRegister() error {
	...
}
```  

在`newRegisterCommand()`函数中，实例化了一个`*cobra.Command`命令对象，该对象中包含两个命令：`ConfigInit()`和`runRegister()`。`ConfigInit()`命令是为fabric-ca-client命令初始化一些配置，这里不做说明，而`runRegister()`中包含客户端注册的主要逻辑：首先实例化一个`lib.Client`结构体，之后导入client端的身份凭证`client.LoadMyIdentity()`，随后发起注册`*Identity.Register()`。  

```go
// fabric-ca/lib/client.go

// Client is the fabric-ca client object
type Client struct {
	// The client's home directory
	HomeDir string `json:"homeDir,omitempty"`
	// The client's configuration
	Config *ClientConfig
	// Denotes if the client object is already initialized
	initialized bool
	// File and directory paths
	keyFile, certFile, idemixCredFile, idemixCredsDir, ipkFile, caCertsDir string
	// The crypto service provider (BCCSP)
	csp bccsp.BCCSP
	// HTTP client associated with this Fabric CA client
	httpClient *http.Client
	// Public key of Idemix issuer
	issuerPublicKey *idemix.IssuerPublicKey
}

// LoadMyIdentity loads the client's identity from disk
func (c *Client) LoadMyIdentity() (*Identity, error) {
	...
	return c.LoadIdentity(c.keyFile, c.certFile, c.idemixCredFile)
}

// LoadIdentity loads an identity from disk
func (c *Client) LoadIdentity(keyFile, certFile, idemixCredFile string) (*Identity, error) {
	...
	return c.NewIdentity(creds)
}

// NewIdentity creates a new identity
func (c *Client) NewIdentity(creds []credential.Credential) (*Identity, error) {
	...
	return NewIdentity(c, name, creds), nil
}
```  

如上，在`LoadMyIdentity()`中会先调用`Init()`来初始化client，然后再调用`LoadIdentity()`函数，从硬盘中导入身份凭证。在`LoadIdentity()`中同样会调用`Init()`来初始化client，之后会调用`NewCredential()`接口来导入**x509**和**idemin**格式的证书。证书读取完成后，调用`NewIdentity()`来创建新的身份认证。至此，身份导入过程就完成了，接下来就是注册了。  

```go  
//fabric-ca/lib/identity.go

// Register registers a new identity
// @param req The registration request
func (i *Identity) Register(req *api.RegistrationRequest) (rr *api.RegistrationResponse, err error) {
	...
}
```

在`Register()`，会将认证请求序列后，通过`Post`请求发送给服务端，并将服务端的应答返回给调用者。  

```go
// Post sends arbitrary request body (reqBody) to an endpoint.
// This adds an authorization header which contains the signature
// of this identity over the body and non-signature part of the authorization header.
// The return value is the body of the response.
func (i *Identity) Post(endpoint string, reqBody []byte, result interface{}, queryParam map[string]string) error {
	...
}
```  

至此，注册命令就结束了。  

## newEnrollCmd(Command).getCommand()  

```go
// fabric-ca/cmd/fabric-ca-client/command/enroll.go

type enrollCmd struct {
	Command
}

func newEnrollCmd(c Command) *enrollCmd {
	enrollCmd := &enrollCmd{c}
	return enrollCmd
}

func (c *enrollCmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "enroll -u http://user:userpw@serverAddr:serverPort",
		Short:   "Enroll an identity",
		Long:    "Enroll identity with Fabric CA server",
		PreRunE: c.preRunEnroll,
		RunE:    c.runEnroll,
	}
	return cmd
}

func (c *enrollCmd) preRunEnroll(cmd *cobra.Command, args []string) error {
	...
}

func (c *enrollCmd) runEnroll(cmd *cobra.Command, args []string) error {
	...
}
```  

从上面的代码可以看出，`enrollCmd`是对`Command`的一层封装，`getCommand()`返回的命令中包含两个操作：`preRunEnroll`，预操作命令，用来初始化命令执行的环境；`runEnroll`，执行留存操作。  

`preRunEnroll()`作用单一，这里就不做赘述了，接下来我们介绍下`runEnroll()`函数。从代码中不难看出，该函数主要是用来保存一些信息的：  

- `ioutil.WriteFile()`：将配置写入本地文件。
- `ID.Store()`：将身份凭证写入本地文件。
- `storeCAChain()`：保存CAChain。
- `storeIssuerPublicKey()`：保存idemix颁发者的公钥。
- `storeIssuerRevocationPublicKey()`：保存idemix颁发者的撤销公钥。

## newReenrollCommand()  

```go
// fabric-ca/cmd/fabric-ca/client/command/reenroll.go

func (c *ClientCmd) newReenrollCommand() *cobra.Command {
	reenrollCmd := &cobra.Command{
		Use:   "reenroll",
		Short: "Reenroll an identity",
		Long:  "Reenroll an identity with Fabric CA server",
		// PreRunE block for this command will check to make sure enrollment
		// information exists before running the command
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}

			err := c.ConfigInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runReenroll()
			if err != nil {
				return err
			}

			return nil
		},
	}
	return reenrollCmd
}

// The client reenroll main logic
func (c *ClientCmd) runReenroll() error {
	...
}
```  

从上述代码中不难看出，`newReenrollCommand()`函数返回一个`*cobra.Command`的命令实例，该命令中包含两个操作：`PreRunE`，预操作，用于初始化环境；`RunE:runReenroll()`，客户端重新留存的只要逻辑。  

在`runReenoll()`中，首先实例化一个`lib.Client`结构体，之后导入client端的身份凭证`client.LoadMyIdentity()`，随后构建了一个`ReenrollmentRequest`请求实例，然后调用`id.Reenroll()`函数，最后重新保存认证信息和CAChain。  

```go  
// fabric-ca/lib/identity.go

// Reenroll reenrolls an existing Identity and returns a new Identity
// @param req The reenrollment request
func (i *Identity) Reenroll(req *api.ReenrollmentRequest) (*EnrollmentResponse, error) {
	...
}
```  

在`Reenroll()`操作最后，调用了`newEnrollmentResponse()`来生成一个`EnrollmentResponse`实例，方便之后的留存操作。  

## newRevokeCommand()

```go
//fabric-ca/cmd/fabric-ca/client/command/revoke.go

func (c *ClientCmd) newRevokeCommand() *cobra.Command {
	revokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an identity",
		Long:  "Revoke an identity with Fabric CA server",
		// PreRunE block for this command will check to make sure enrollment
		// information exists before running the command
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}

			err := c.ConfigInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runRevoke(cmd)
			if err != nil {
				return err
			}

			return nil
		},
	}
	util.RegisterFlags(c.myViper, revokeCmd.Flags(), &c.revokeParams, nil)
	return revokeCmd
}

// The client revoke main logic
func (c *ClientCmd) runRevoke(cmd *cobra.Command) error {
	...
}
```  

`newRevokeCommand()`同样返回了个命令实例，执行两个操作：`PreRunE:ConfigInit()`，预操作，初始化环境；`RunE:runRevoke()`，客户端撤销操作主逻辑。  

在`runRevoke()`中，首先实例化一个`lib.Client`结构体，之后导入client端的身份凭证`client.LoadMyIdentity()`，随后构建了一个`RevocationRequest`请求实例，然后调用`id.Revoke()`函数，最后保存撤销列表（`storeCRL()`）。  

```go  
// fabric-ca/lib/identity.go  

// 撤销与'i'相关的身份凭证
func (i *Identity) Revoke(req *api.RevocationRequest) (*api.RevocationResponse, error) {
	log.Debugf("Entering identity.Revoke %+v", req)
	reqBody, err := util.Marshal(req, "RevocationRequest")
	if err != nil {
		return nil, err
	}
	var result revocationResponseNet
	err = i.Post("revoke", reqBody, &result, nil)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully revoked certificates: %+v", req)
	crl, err := util.B64Decode(result.CRL)
	if err != nil {
		return nil, err
	}
	return &api.RevocationResponse{RevokedCerts: result.RevokedCerts, CRL: crl}, nil
}
```  

## newGetCAInfoCmd(c).getCommand()

```go  
// fabric-ca/cmd/fabric-ca/client/command/getcainfo.go

const (
	// GetCAInfoCmdUsage is the usage text for getCACert command
	GetCAInfoCmdUsage = "getcainfo -u http://serverAddr:serverPort -M <MSP-directory>"
	// GetCAInfoCmdShortDesc is the short description for getCACert command
	GetCAInfoCmdShortDesc = "Get CA certificate chain and Idemix public key"
)

type getCAInfoCmd struct {
	Command
}

func newGetCAInfoCmd(c Command) *getCAInfoCmd {
	getcacertcmd := &getCAInfoCmd{c}
	return getcacertcmd
}

func (c *getCAInfoCmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     GetCAInfoCmdUsage,
		Short:   GetCAInfoCmdShortDesc,
		Aliases: []string{"getcacert"},
		PreRunE: c.preRunGetCACert,
		RunE:    c.runGetCACert,
	}
	return cmd
}

func (c *getCAInfoCmd) preRunGetCACert(cmd *cobra.Command, args []string) error {
	...
}

func (c *getCAInfoCmd) runGetCACert(cmd *cobra.Command, args []string) error {
	...
}
```

`newGetCAInfoCmd(c Command).getCommand()`返回一个命令实例，包含两个操作：`PreRunE:preRunGetCACert`，预操作，初始化命令环境；`RunE:runGetCACert()`，获取并存储CA信息。这个两个命令操作很简单，源码中也写的很明白，这里就不再赘述了。  

## newGenCsrCommand()  

```go  
// fabric-ca/cmd/fabric-ca-client/command/gencsr.go

func (c *ClientCmd) newGenCsrCommand() *cobra.Command {
	// initCmd represents the init command
	gencsrCmd := &cobra.Command{
		Use:   "gencsr",
		Short: "Generate a CSR",
		Long:  "Generate a Certificate Signing Request for an identity",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}

			err := c.ConfigInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runGenCSR(cmd)
			if err != nil {
				return err
			}
			return nil
		},
	}
	gencsrCmd.Flags().StringVar(&c.csrCommonName, "csr.cn", "", "The common name for the certificate signing request")
	return gencsrCmd
}

// The gencsr main logic
func (c *ClientCmd) runGenCSR(cmd *cobra.Command) error {
	...
}
```  

`newGenCsrCommand()`返回一个命令实例，包含两个操作：`PreRunE:ConfigInit`，预操作，初始化命令环境；`RunE:runGenCSR()`，生成证书请求的主逻辑。  

在`runGenCSR()`中，调用了`GenCSR()`函数来生成证书请求：  

```go
// fabric-ca/lib/clientconfig.go

// GenCSR generates a certificate signing request and writes the CSR to a file.
func (c *ClientConfig) GenCSR(home string) error {
	...
}

// fabric-ca/lib/client.go
// GenCSR generates a CSR (Certificate Signing Request)
func (c *Client) GenCSR(req *api.CSRInfo, id string) ([]byte, bccsp.Key, error) {
	...
}
```  

## newGenCRLCommand()  

```go
// fabric-ca/cmd/fabric-ca-client/command/gencrl.go

func (c *ClientCmd) newGenCRLCommand() *cobra.Command {
	var genCrlCmd = &cobra.Command{
		Use:   "gencrl",
		Short: "Generate a CRL",
		Long:  "Generate a Certificate Revocation List",
		// PreRunE block for this command will load client configuration
		// before running the command
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}
			err := c.ConfigInit()
			if err != nil {
				return err
			}
			log.Debugf("Client configuration settings: %+v", c.clientCfg)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runGenCRL()
			if err != nil {
				return err
			}
			return nil
		},
	}
	util.RegisterFlags(c.myViper, genCrlCmd.Flags(), &c.crlParams, nil)
	return genCrlCmd
}

// The client register main logic
func (c *ClientCmd) runGenCRL() error {
	...
}

// Store the CRL
func storeCRL(config *lib.ClientConfig, crl []byte) error {
	...
}
```  

`newGenCRLCommand()`返回一个命令实例，包含两个操作：`PreRunE:ConfigInit`，预操作，初始化命令环境；`RunE:runGenCRL()`，证书撤销请求的主逻辑。  

在`runGenCRL()`中，首先实例化一个`lib.Client`结构体，之后导入client端的身份凭证`client.LoadMyIdentity()`，随后构建了一个`GenCRLRequest`请求实例，然后调用`id.GenCRL()`函数，最后保存证书撤销列表。  

```go
// fabric-ca/lib/identity.go

// GenCRL generates CRL
func (i *Identity) GenCRL(req *api.GenCRLRequest) (*api.GenCRLResponse, error) {
	...
}
```  

## newIdentityCommand()  

```go
// fabric-ca/cmd/fabric-ca/client/command/identity.go
type identityArgs struct {
	id     string
	json   string
	add    api.AddIdentityRequest
	modify api.ModifyIdentityRequest
	remove api.RemoveIdentityRequest
}

func (c *ClientCmd) newIdentityCommand() *cobra.Command {
	identityCmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage identities",
		Long:  "Manage identities",
	}
	identityCmd.AddCommand(c.newListIdentityCommand())
	identityCmd.AddCommand(c.newAddIdentityCommand())
	identityCmd.AddCommand(c.newModifyIdentityCommand())
	identityCmd.AddCommand(c.newRemoveIdentityCommand())
	return identityCmd
}

func (c *ClientCmd) newListIdentityCommand() *cobra.Command {
	...
}

func (c *ClientCmd) newAddIdentityCommand() *cobra.Command {
	...
}

func (c *ClientCmd) newModifyIdentityCommand() *cobra.Command {
	...
}

func (c *ClientCmd) newRemoveIdentityCommand() *cobra.Command {
	...
}

// The client side logic for executing list identity command
func (c *ClientCmd) runListIdentity(cmd *cobra.Command, args []string) error {
	...
}

// The client side logic for adding an identity
func (c *ClientCmd) runAddIdentity(cmd *cobra.Command, args []string) error {
	...
}

// The client side logic for modifying an identity
func (c *ClientCmd) runModifyIdentity(cmd *cobra.Command, args []string) error {
	...
}

// The client side logic for removing an identity
func (c *ClientCmd) runRemoveIdentity(cmd *cobra.Command, args []string) error {
	...
}

func (c *ClientCmd) identityPreRunE(cmd *cobra.Command, args []string) error {
	...
}

...
```  

`newIdentityCommand()`返回一个`*cobra.Command`的命令实例，该命令中包含四个命令：`newListIdentityCommand()`、`newAddIdentityCommand()`、`newModifyIdentityCommand()`和`newRemoveIdentityCommand()`。  

### newListIdentityCommand()  

`newListIdentityCommand()`命令中包含两个操作：`PreRunE: ConfigInit()`，预操作，初始化环境；`RunE: runListIdentity()`，客户端的逻辑，罗列出所有认证的命令。  

### newAddIdentityCommand()  

`newAddIdentityCommand()`命令中包含两个操作：`PreRunE: ConfigInit()`，预操作，初始化环境；`RunE: runAddIdentity()`，客户端的逻辑，新增认证。  

### newModifyIdentityCommand()  

`newModifyIdentityCommand()`命令中包含两个操作：`PreRunE: ConfigInit()`，预操作，初始化环境；`RunE: runModifyIdentity()`，客户端的逻辑，修改指定认证。  

### newRemoveIdentityCommand()  

`newRemoveIdentityCommand()`命令中包含两个操作：`PreRunE: ConfigInit()`，预操作，初始化环境；`RunE: runRemoveIdentity()`，客户端的逻辑，移除指定认证。  

## 其它  

剩下的两个命令：`newAffiliationCommand()`和`createCertificateCommand()`，逻辑比较简单，这里就不再赘述了。