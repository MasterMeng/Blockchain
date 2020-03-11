# Fabric-ca client端初始化过程源码分析  

本文从Fabric-ca源码入手，简单分析client启动时的过程。Fabric-ca源码可以从[github.com](https://github.com/hyperledger/fabric-ca/releases)下载，本文以**v1.4.6**为例进行简单分析。  

与server相似，本文也是从**main.go**开始：  

```go  
// fabric-ca/cmd/fabric-ca-client/main.go

package main

import (
	"os"

	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
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

// Execute runs this ClientCmd
func (c *ClientCmd) Execute() error {
	return c.rootCmd.Execute()
}

// init initializes the ClientCmd instance
// It intializes the cobra root and sub commands and
// registers command flgs with viper
func (c *ClientCmd) init() {
	c.rootCmd = &cobra.Command{
		Use:   cmdName,
		Short: longName,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := c.checkAndEnableProfiling()
			if err != nil {
				return err
			}
			util.CmdRunBegin(c.myViper)
			cmd.SilenceUsage = true
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if c.profileMode != "" && c.profileInst != nil {
				c.profileInst.Stop()
			}
			return nil
		},
	}
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
	log.Level = log.LevelInfo
}
```  

在`NewCommand()`函数中，创建了一个`*ClientCmd`的对象，之后，调用该对象的`init()`方法。在`init()`方法中，首先实例化了`*ClientCmd.rootCmd`，其中会要执行`checkAndEnableProfiling()`来检查运行环境：  

```go  
// checkAndEnableProfiling checks for the FABRIC_CA_CLIENT_PROFILE_MODE
// env variable, if it is set to "cpu", cpu profiling is enbled;
// if it is set to "heap", heap profiling is enabled
func (c *ClientCmd) checkAndEnableProfiling() error {
	c.profileMode = strings.ToLower(os.Getenv(fabricCAClientProfileMode))
	if c.profileMode != "" {
		wd, err := os.Getwd()
		if err != nil {
			wd = os.Getenv("HOME")
		}
		opt := profile.ProfilePath(wd)
		switch c.profileMode {
		case "cpu":
			c.profileInst = profile.Start(opt, profile.CPUProfile)
		case "heap":
			c.profileInst = profile.Start(opt, profile.MemProfileRate(2048))
		default:
			msg := fmt.Sprintf("Invalid value for the %s environment variable; found '%s', expecting 'cpu' or 'heap'",
				fabricCAClientProfileMode, c.profileMode)
			return errors.New(msg)
		}
	}
	return nil
}

// registerFlags registers command flags with viper
func (c *ClientCmd) registerFlags() {
	// Get the default config file path
	cfg := util.GetDefaultConfigFile(cmdName)

	// All env variables must be prefixed
	c.myViper.SetEnvPrefix(envVarPrefix)
	c.myViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	host, err := os.Hostname()
	if err != nil {
		log.Error(err)
	}

	// Set global flags used by all commands
	pflags := c.rootCmd.PersistentFlags()
	pflags.StringVarP(&c.cfgFileName, "config", "c", "", "Configuration file")
	pflags.MarkHidden("config")
	// Don't want to use the default parameter for StringVarP. Need to be able to identify if home directory was explicitly set
	pflags.StringVarP(&c.homeDirectory, "home", "H", "", fmt.Sprintf("Client's home directory (default \"%s\")", filepath.Dir(cfg)))
	pflags.StringSliceVarP(
		&c.cfgAttrs, "id.attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	pflags.StringSliceVarP(
		&c.cfgAttrReqs, "enrollment.attrs", "", nil, "A list of comma-separated attribute requests of the form <name>[:opt] (e.g. foo,bar:opt)")
	util.FlagString(c.myViper, pflags, "myhost", "m", host,
		"Hostname to include in the certificate signing request during enrollment")
	pflags.StringSliceVarP(
		&c.cfgCsrNames, "csr.names", "", nil, "A list of comma-separated CSR names of the form <name>=<value> (e.g. C=CA,O=Org1)")

	c.clientCfg = &lib.ClientConfig{}
	tags := map[string]string{
		"help.csr.cn":                "The common name field of the certificate signing request",
		"help.csr.serialnumber":      "The serial number in a certificate signing request",
		"help.csr.hosts":             "A list of comma-separated host names in a certificate signing request",
		"skip.csp.pluginopts.config": "true", // Skipping because this a map
	}
	err = util.RegisterFlags(c.myViper, pflags, c.clientCfg, tags)
	if err != nil {
		panic(err)
	}
}
```  

之后会调用`AddCommand()`函数来添加`newRegisterCommand()`、`newEnrollCmd(c).getCommand()`、`newReenrollCommand()`、`newRevokeCommand()`、`newGetCAInfoCmd(c).getCommand()`、`newGenCsrCommand()`、`newGenCRLCommand()`、`newIdentityCommand()`、`newAffiliationCommand()`、`createCertificateCommand()`和获取client版本的命令。随后执行`c.registerFlags()`操作。`registerFlags()`函数中主要是注册一些命令行参数，这里就不细究了。  

## newRegisterCommand()  

```go  
// fabric-ca/cmd/fabric-ca-client/command/register.go

func (c *ClientCmd) newRegisterCommand() *cobra.Command {
	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Register an identity",
		Long:  "Register an identity with Fabric CA server",
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
			err := c.runRegister()
			if err != nil {
				return err
			}

			return nil
		},
	}
	return registerCmd
}

// The client register main logic
func (c *ClientCmd) runRegister() error {
	log.Debug("Entered runRegister")

	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	c.clientCfg.ID.CAName = c.clientCfg.CAName
	resp, err := id.Register(&c.clientCfg.ID)
	if err != nil {
		return err
	}

	fmt.Printf("Password: %s\n", resp.Secret)

	return nil
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
	err := c.Init()
	if err != nil {
		return nil, err
	}
	return c.LoadIdentity(c.keyFile, c.certFile, c.idemixCredFile)
}

// LoadIdentity loads an identity from disk
func (c *Client) LoadIdentity(keyFile, certFile, idemixCredFile string) (*Identity, error) {
	log.Debugf("Loading identity: keyFile=%s, certFile=%s", keyFile, certFile)
	err := c.Init()
	if err != nil {
		return nil, err
	}

	var creds []credential.Credential
	var x509Found, idemixFound bool
	x509Cred := x509cred.NewCredential(certFile, keyFile, c)
	err = x509Cred.Load()
	if err == nil {
		x509Found = true
		creds = append(creds, x509Cred)
	} else {
		log.Debugf("No X509 credential found at %s, %s", keyFile, certFile)
	}

	idemixCred := idemixcred.NewCredential(idemixCredFile, c)
	err = idemixCred.Load()
	if err == nil {
		idemixFound = true
		creds = append(creds, idemixCred)
	} else {
		log.Debugf("No Idemix credential found at %s", idemixCredFile)
	}

	if !x509Found && !idemixFound {
		return nil, errors.New("Identity does not posses any enrollment credentials")
	}

	return c.NewIdentity(creds)
}

// NewIdentity creates a new identity
func (c *Client) NewIdentity(creds []credential.Credential) (*Identity, error) {
	if len(creds) == 0 {
		return nil, errors.New("No credentials spcified. Atleast one credential must be specified")
	}
	name, err := creds[0].EnrollmentID()
	if err != nil {
		return nil, err
	}
	if len(creds) == 1 {
		return NewIdentity(c, name, creds), nil
	}

	//TODO: Get the enrollment ID from the creds...they all should return same value
	// for i := 1; i < len(creds); i++ {
	// 	localid, err := creds[i].EnrollmentID()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if localid != name {
	// 		return nil, errors.New("Specified credentials belong to different identities, they should be long to same identity")
	// 	}
	// }
	return NewIdentity(c, name, creds), nil
}
```  

如上，在`LoadMyIdentity()`中会先调用`Init()`来初始化client，然后再调用`LoadIdentity()`函数，从硬盘中导入身份凭证。在`LoadIdentity()`中同样会调用`Init()`来初始化client，之后会调用`NewCredential()`接口来导入**x509**和**idemin**格式的证书。证书读取完成后，调用`NewIdentity()`来创建新的身份认证。至此，身份导入过程就完成了，接下来就是注册了。  

```go  
//fabric-ca/lib/identity.go

// Register registers a new identity
// @param req The registration request
func (i *Identity) Register(req *api.RegistrationRequest) (rr *api.RegistrationResponse, err error) {
	log.Debugf("Register %+v", req)
	if req.Name == "" {
		return nil, errors.New("Register was called without a Name set")
	}

	reqBody, err := util.Marshal(req, "RegistrationRequest")
	if err != nil {
		return nil, err
	}

	// Send a post to the "register" endpoint with req as body
	resp := &api.RegistrationResponse{}
	err = i.Post("register", reqBody, resp, nil)
	if err != nil {
		return nil, err
	}

	log.Debug("The register request completed successfully")
	return resp, nil
}
```

在`Register()`，会将认证请求序列后，通过`Post`请求发送给服务端，并将服务端的应答返回给调用者。  

```go
// Post sends arbitrary request body (reqBody) to an endpoint.
// This adds an authorization header which contains the signature
// of this identity over the body and non-signature part of the authorization header.
// The return value is the body of the response.
func (i *Identity) Post(endpoint string, reqBody []byte, result interface{}, queryParam map[string]string) error {
	req, err := i.client.newPost(endpoint, reqBody)
	if err != nil {
		return err
	}
	if queryParam != nil {
		for key, value := range queryParam {
			addQueryParm(req, key, value)
		}
	}
	err = i.addTokenAuthHdr(req, reqBody)
	if err != nil {
		return err
	}
	return i.client.SendReq(req, result)
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
	if len(args) > 0 {
		return errors.Errorf(extraArgsError, args, cmd.UsageString())
	}

	err := c.ConfigInit()
	if err != nil {
		return err
	}

	log.Debugf("Client configuration settings: %+v", c.GetClientCfg())

	return nil
}

func (c *enrollCmd) runEnroll(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runEnroll")
	cfgFileName := c.GetCfgFileName()
	cfg := c.GetClientCfg()
	resp, err := cfg.Enroll(cfg.URL, filepath.Dir(cfgFileName))
	if err != nil {
		return err
	}

	ID := resp.Identity

	cfgFile, err := ioutil.ReadFile(cfgFileName)
	if err != nil {
		return errors.Wrapf(err, "Failed to read file at '%s'", cfgFileName)
	}

	cfgStr := strings.Replace(string(cfgFile), "<<<ENROLLMENT_ID>>>", ID.GetName(), 1)

	err = ioutil.WriteFile(cfgFileName, []byte(cfgStr), 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to write file at '%s'", cfgFileName)
	}

	err = ID.Store()
	if err != nil {
		return errors.WithMessage(err, "Failed to store enrollment information")
	}

	// Store issuer public key
	err = storeCAChain(cfg, &resp.CAInfo)
	if err != nil {
		return err
	}
	err = storeIssuerPublicKey(cfg, &resp.CAInfo)
	if err != nil {
		return err
	}
	return storeIssuerRevocationPublicKey(cfg, &resp.CAInfo)
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
	log.Debug("Entered runReenroll")

	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.ReenrollmentRequest{
		Label:   c.clientCfg.Enrollment.Label,
		Profile: c.clientCfg.Enrollment.Profile,
		CSR:     &c.clientCfg.CSR,
		CAName:  c.clientCfg.CAName,
	}

	resp, err := id.Reenroll(req)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed to reenroll '%s'", id.GetName()))
	}

	err = resp.Identity.Store()
	if err != nil {
		return err
	}

	err = storeCAChain(c.clientCfg, &resp.CAInfo)
	if err != nil {
		return err
	}

	return nil
}
```  

从上述代码中不难看出，`newReenrollCommand()`函数返回一个`*cobra.Command`的命令实例，该命令中包含两个操作：`PreRunE`，预操作，用于初始化环境；`RunE:runReenroll()`，客户端重新留存的只要逻辑。  

在`runReenoll()`中，首先实例化一个`lib.Client`结构体，之后导入client端的身份凭证`client.LoadMyIdentity()`，随后构建了一个`ReenrollmentRequest`请求实例，然后调用`id.Reenroll()`函数，最后重新保存认证信息和CAChain。  

```go  
// fabric-ca/lib/identity.go

// Reenroll reenrolls an existing Identity and returns a new Identity
// @param req The reenrollment request
func (i *Identity) Reenroll(req *api.ReenrollmentRequest) (*EnrollmentResponse, error) {
	log.Debugf("Reenrolling %s", util.StructToString(req))

	csrPEM, key, err := i.client.GenCSR(req.CSR, i.GetName())
	if err != nil {
		return nil, err
	}

	reqNet := &api.ReenrollmentRequestNet{
		CAName:   req.CAName,
		AttrReqs: req.AttrReqs,
	}

	// Get the body of the request
	if req.CSR != nil {
		reqNet.SignRequest.Hosts = req.CSR.Hosts
	}
	reqNet.SignRequest.Request = string(csrPEM)
	reqNet.SignRequest.Profile = req.Profile
	reqNet.SignRequest.Label = req.Label

	body, err := util.Marshal(reqNet, "SignRequest")
	if err != nil {
		return nil, err
	}
	var result common.EnrollmentResponseNet
	err = i.Post("reenroll", body, &result, nil)
	if err != nil {
		return nil, err
	}
	return i.client.newEnrollmentResponse(&result, i.GetName(), key)
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
	log.Debug("Entered runRevoke")

	var err error

	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	// aki and serial # are required to revoke a certificate. The enrollment ID
	// is required to revoke an identity. So, either aki and serial must be
	// specified OR enrollment ID must be specified, else return an error.
	// Note that all three can be specified, in which case server will revoke
	// certificate associated with the specified aki, serial number.
	if (c.clientCfg.Revoke.Name == "") && (c.clientCfg.Revoke.AKI == "" ||
		c.clientCfg.Revoke.Serial == "") {
		cmd.Usage()
		return errInput
	}

	req := &api.RevocationRequest{
		Name:   c.clientCfg.Revoke.Name,
		Serial: c.clientCfg.Revoke.Serial,
		AKI:    c.clientCfg.Revoke.AKI,
		Reason: c.clientCfg.Revoke.Reason,
		GenCRL: c.revokeParams.GenCRL,
		CAName: c.clientCfg.CAName,
	}
	result, err := id.Revoke(req)

	if err != nil {
		return err
	}
	log.Infof("Sucessfully revoked certificates: %+v", result.RevokedCerts)

	if req.GenCRL {
		return storeCRL(c.clientCfg, result.CRL)
	}
	return nil
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
	if len(args) > 0 {
		return errors.Errorf(extraArgsError, args, cmd.UsageString())
	}

	err := c.ConfigInit()
	if err != nil {
		return err
	}

	log.Debugf("Client configuration settings: %+v", c.GetClientCfg())

	return nil
}

func (c *getCAInfoCmd) runGetCACert(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runGetCACert")

	client := &lib.Client{
		HomeDir: filepath.Dir(c.GetCfgFileName()),
		Config:  c.GetClientCfg(),
	}

	req := &api.GetCAInfoRequest{
		CAName: c.GetClientCfg().CAName,
	}

	si, err := client.GetCAInfo(req)
	if err != nil {
		return err
	}

	err = storeCAChain(client.Config, si)
	if err != nil {
		return err
	}
	err = storeIssuerPublicKey(client.Config, si)
	if err != nil {
		return err
	}
	return storeIssuerRevocationPublicKey(client.Config, si)
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
	log.Debug("Entered runGenCSR")

	if c.csrCommonName != "" {
		c.clientCfg.CSR.CN = c.csrCommonName
	}

	err := c.clientCfg.GenCSR(filepath.Dir(c.cfgFileName))
	if err != nil {
		return err
	}

	return nil
}
```  

`newGenCsrCommand()`返回一个命令实例，包含两个操作：`PreRunE:ConfigInit`，预操作，初始化命令环境；`RunE:runGenCSR()`，生成证书请求的主逻辑。  

在`runGenCSR()`中，调用了`GenCSR()`函数来生成整数请求：  

```go
// fabric-ca/lib/clientconfig.go

// GenCSR generates a certificate signing request and writes the CSR to a file.
func (c *ClientConfig) GenCSR(home string) error {

	client := &Client{HomeDir: home, Config: c}
	// Generate the CSR

	err := client.Init()
	if err != nil {
		return err
	}

	if c.CSR.CN == "" {
		return errors.Errorf("CSR common name not specified; use '--csr.cn' flag")
	}

	csrPEM, _, err := client.GenCSR(&c.CSR, c.CSR.CN)
	if err != nil {
		return err
	}

	csrFile := path.Join(client.Config.MSPDir, "signcerts", fmt.Sprintf("%s.csr", c.CSR.CN))
	err = util.WriteFile(csrFile, csrPEM, 0644)
	if err != nil {
		return errors.WithMessage(err, "Failed to store the CSR")
	}
	log.Infof("Stored CSR at %s", csrFile)
	return nil
}

// fabric-ca/lib/client.go
// GenCSR generates a CSR (Certificate Signing Request)
func (c *Client) GenCSR(req *api.CSRInfo, id string) ([]byte, bccsp.Key, error) {
	log.Debugf("GenCSR %+v", req)

	err := c.Init()
	if err != nil {
		return nil, nil, err
	}

	cr := c.newCertificateRequest(req)
	cr.CN = id

	if (cr.KeyRequest == nil) || (cr.KeyRequest.Size() == 0 && cr.KeyRequest.Algo() == "") {
		cr.KeyRequest = newCfsslBasicKeyRequest(api.NewBasicKeyRequest())
	}

	key, cspSigner, err := util.BCCSPKeyRequestGenerate(cr, c.csp)
	if err != nil {
		log.Debugf("failed generating BCCSP key: %s", err)
		return nil, nil, err
	}

	csrPEM, err := csr.Generate(cspSigner, cr)
	if err != nil {
		log.Debugf("failed generating CSR: %s", err)
		return nil, nil, err
	}

	return csrPEM, key, nil
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
	log.Debug("Entered runGenCRL")
	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}
	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}
	var revokedAfter, revokedBefore time.Time
	if c.crlParams.RevokedAfter != "" {
		revokedAfter, err = time.Parse(time.RFC3339, c.crlParams.RevokedAfter)
		if err != nil {
			return errors.Wrap(err, "Invalid 'revokedafter' value")
		}
	}
	if c.crlParams.RevokedBefore != "" {
		revokedBefore, err = time.Parse(time.RFC3339, c.crlParams.RevokedBefore)
		if err != nil {
			return errors.Wrap(err, "Invalid 'revokedbefore' value")
		}
	}
	if !revokedBefore.IsZero() && revokedAfter.After(revokedBefore) {
		return errors.Errorf("Invalid revokedafter value '%s'. It must not be a timestamp greater than revokedbefore value '%s'",
			c.crlParams.RevokedAfter, c.crlParams.RevokedBefore)
	}

	var expireAfter, expireBefore time.Time
	if c.crlParams.ExpireAfter != "" {
		expireAfter, err = time.Parse(time.RFC3339, c.crlParams.ExpireAfter)
		if err != nil {
			return errors.Wrap(err, "Invalid 'expireafter' value")
		}
	}
	if c.crlParams.ExpireBefore != "" {
		expireBefore, err = time.Parse(time.RFC3339, c.crlParams.ExpireBefore)
		if err != nil {
			return errors.Wrap(err, "Invalid 'expirebefore' value")
		}
	}
	if !expireBefore.IsZero() && expireAfter.After(expireBefore) {
		return errors.Errorf("Invalid expireafter value '%s'. It must not be a timestamp greater than expirebefore value '%s'",
			c.crlParams.ExpireAfter, c.crlParams.ExpireBefore)
	}
	req := &api.GenCRLRequest{
		CAName:        c.clientCfg.CAName,
		RevokedAfter:  revokedAfter,
		RevokedBefore: revokedBefore,
		ExpireAfter:   expireAfter,
		ExpireBefore:  expireBefore,
	}
	resp, err := id.GenCRL(req)
	if err != nil {
		return err
	}
	log.Info("Successfully generated the CRL")
	err = storeCRL(c.clientCfg, resp.CRL)
	if err != nil {
		return err
	}
	return nil
}

// Store the CRL
func storeCRL(config *lib.ClientConfig, crl []byte) error {
	dirName := path.Join(config.MSPDir, crlsFolder)
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		mkdirErr := os.MkdirAll(dirName, os.ModeDir|0755)
		if mkdirErr != nil {
			return errors.Wrapf(mkdirErr, "Failed to create directory %s", dirName)
		}
	}
	fileName := path.Join(dirName, crlFile)
	err := util.WriteFile(fileName, crl, 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to write CRL to the file %s", fileName)
	}
	log.Infof("Successfully stored the CRL in the file %s", fileName)
	return nil
}
```  

`newGenCRLCommand()`返回一个命令实例，包含两个操作：`PreRunE:ConfigInit`，预操作，初始化命令环境；`RunE:runGenCRL()`，证书撤销请求的主逻辑。  

在`runGenCRL()`中，首先实例化一个`lib.Client`结构体，之后导入client端的身份凭证`client.LoadMyIdentity()`，随后构建了一个`GenCRLRequest`请求实例，然后调用`id.GenCRL()`函数，最后保存证书撤销列表。  

```go
// fabric-ca/lib/identity.go

// GenCRL generates CRL
func (i *Identity) GenCRL(req *api.GenCRLRequest) (*api.GenCRLResponse, error) {
	log.Debugf("Entering identity.GenCRL %+v", req)
	reqBody, err := util.Marshal(req, "GenCRLRequest")
	if err != nil {
		return nil, err
	}
	var result genCRLResponseNet
	err = i.Post("gencrl", reqBody, &result, nil)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully generated CRL: %+v", req)
	crl, err := util.B64Decode(result.CRL)
	if err != nil {
		return nil, err
	}
	return &api.GenCRLResponse{CRL: crl}, nil
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
	identityListCmd := &cobra.Command{
		Use:   "list",
		Short: "List identities",
		Long:  "List identities visible to caller",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			c.SetDefaultLogLevel(calog.WARNING)
			err := c.ConfigInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: c.runListIdentity,
	}
	flags := identityListCmd.Flags()
	flags.StringVarP(
		&c.dynamicIdentity.id, "id", "", "", "Get identity information from the fabric-ca server")
	return identityListCmd
}

func (c *ClientCmd) newAddIdentityCommand() *cobra.Command {
	identityAddCmd := &cobra.Command{
		Use:     "add <id>",
		Short:   "Add identity",
		Long:    "Add an identity",
		Example: "fabric-ca-client identity add user1 --type peer",
		PreRunE: c.identityPreRunE,
		RunE:    c.runAddIdentity,
	}
	flags := identityAddCmd.Flags()
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.add, nil)
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for adding a new identity")
	return identityAddCmd
}

func (c *ClientCmd) newModifyIdentityCommand() *cobra.Command {
	identityModifyCmd := &cobra.Command{
		Use:     "modify <id>",
		Short:   "Modify identity",
		Long:    "Modify an existing identity",
		Example: "fabric-ca-client identity modify user1 --type peer",
		PreRunE: c.identityPreRunE,
		RunE:    c.runModifyIdentity,
	}
	flags := identityModifyCmd.Flags()
	tags := map[string]string{
		"skip.id": "true",
	}
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.modify, tags)
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for modifying an existing identity")
	return identityModifyCmd
}

func (c *ClientCmd) newRemoveIdentityCommand() *cobra.Command {
	identityRemoveCmd := &cobra.Command{
		Use:     "remove <id>",
		Short:   "Remove identity",
		Long:    "Remove an identity",
		Example: "fabric-ca-client identity remove user1",
		PreRunE: c.identityPreRunE,
		RunE:    c.runRemoveIdentity,
	}
	flags := identityRemoveCmd.Flags()
	flags.BoolVarP(
		&c.dynamicIdentity.remove.Force, "force", "", false, "Forces removing your own identity")
	return identityRemoveCmd
}

// The client side logic for executing list identity command
func (c *ClientCmd) runListIdentity(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runListIdentity")

	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	if c.dynamicIdentity.id != "" {
		resp, err := id.GetIdentity(c.dynamicIdentity.id, c.clientCfg.CAName)
		if err != nil {
			return err
		}

		fmt.Printf("Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Attributes: %+v\n", resp.ID, resp.Type, resp.Affiliation, resp.MaxEnrollments, resp.Attributes)
		return nil
	}

	err = id.GetAllIdentities(c.clientCfg.CAName, lib.IdentityDecoder)
	if err != nil {
		return err
	}

	return nil
}

// The client side logic for adding an identity
func (c *ClientCmd) runAddIdentity(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runAddIdentity: %+v", c.dynamicIdentity)
	if c.dynamicIdentity.json != "" && checkOtherFlags(cmd) {
		return errors.Errorf("Can't use 'json' flag in conjunction with other flags")
	}

	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.AddIdentityRequest{}

	if c.dynamicIdentity.json != "" {
		err := util.Unmarshal([]byte(c.dynamicIdentity.json), &req, "addIdentity")
		if err != nil {
			return errors.Wrap(err, "Invalid value for --json option")
		}
	} else {
		req = &c.dynamicIdentity.add
		req.Attributes = c.clientCfg.ID.Attributes
	}

	req.ID = args[0]
	req.CAName = c.clientCfg.CAName
	resp, err := id.AddIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added identity - Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Secret: %s, Attributes: %+v\n", resp.ID, resp.Type, resp.Affiliation, resp.MaxEnrollments, resp.Secret, resp.Attributes)
	return nil
}

// The client side logic for modifying an identity
func (c *ClientCmd) runModifyIdentity(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runModifyIdentity: %+v", c.dynamicIdentity)
	if c.dynamicIdentity.json != "" && checkOtherFlags(cmd) {
		return errors.Errorf("Can't use 'json' flag in conjunction with other flags")
	}

	req := &api.ModifyIdentityRequest{}

	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	if c.dynamicIdentity.json != "" {
		err := util.Unmarshal([]byte(c.dynamicIdentity.json), req, "modifyIdentity")
		if err != nil {
			return errors.Wrap(err, "Invalid value for --json option")
		}
	} else {
		req = &c.dynamicIdentity.modify
		req.Attributes = c.clientCfg.ID.Attributes
	}

	req.ID = args[0]
	req.CAName = c.clientCfg.CAName
	resp, err := id.ModifyIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully modified identity - Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Secret: %s, Attributes: %+v\n", resp.ID, resp.Type, resp.Affiliation, resp.MaxEnrollments, resp.Secret, resp.Attributes)
	return nil
}

// The client side logic for removing an identity
func (c *ClientCmd) runRemoveIdentity(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runRemoveIdentity: %+v", c.dynamicIdentity)

	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &c.dynamicIdentity.remove
	req.ID = args[0]
	req.CAName = c.clientCfg.CAName
	resp, err := id.RemoveIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully removed identity - Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Attributes: %+v\n", resp.ID, resp.Type, resp.Affiliation, resp.MaxEnrollments, resp.Attributes)
	return nil
}

func (c *ClientCmd) identityPreRunE(cmd *cobra.Command, args []string) error {
	err := argsCheck(args, "Identity")
	if err != nil {
		return err
	}

	err = c.ConfigInit()
	if err != nil {
		return err
	}

	log.Debugf("Client configuration settings: %+v", c.clientCfg)

	return nil
}

// checkOtherFlags returns true if other flags besides '--json' are set
// Viper.IsSet does not work correctly if there are defaults defined for
// flags. This is a workaround until this bug is addressed in Viper.
// Viper Bug: https://github.com/spf13/viper/issues/276
func checkOtherFlags(cmd *cobra.Command) bool {
	checkFlags := []string{"id", "type", "affiliation", "secret", "maxenrollments", "attrs"}
	flags := cmd.Flags()
	for _, checkFlag := range checkFlags {
		flag := flags.Lookup(checkFlag)
		if flag != nil {
			if flag.Changed {
				return true
			}
		}
	}

	return false
}

func argsCheck(args []string, field string) error {
	if len(args) == 0 {
		return errors.Errorf("%s name is required", field)
	}
	if len(args) > 1 {
		return errors.Errorf("Unknown argument '%s', only the identity name should be passed in as non-flag argument", args[1])
	}
	return nil
}
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