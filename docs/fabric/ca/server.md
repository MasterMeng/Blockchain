# Fabric-ca server端初始化过程源码分析  

本文从Fabric-ca源码入手，简单分析server启动时的过程。Fabric-ca源码可以从[github.com](https://github.com/hyperledger/fabric-ca/releases)下载，本文以**v1.4.6**为例进行简单分析。  

Fabric-ca是有go语言编写的，与C/C++类似，程序都有一个**mian()**函数，不同的是，go的main函数必须存在于`package main`中：  

```go
// fabric-ca/cmd/fabric-ca-server/main.go

package main

import "os"

var (
	blockingStart = true
)

// The fabric-ca server main
func main() {
	if err := RunMain(os.Args); err != nil {
		os.Exit(1)
	}
}

// RunMain is the fabric-ca server main
func RunMain(args []string) error {
	// Save the os.Args
	saveOsArgs := os.Args
	os.Args = args

	cmdName := ""
	if len(args) > 1 {
		cmdName = args[1]
	}
	scmd := NewCommand(cmdName, blockingStart)

	// Execute the command
	err := scmd.Execute()

	// Restore original os.Args
	os.Args = saveOsArgs

	return err
}
```  

从上述代码中可以看出，程序执行时会调用`RunMain()`函数，而在`RunMain()`中调用`NewCommand()`来生成一个`*ServerCmd`对象，之后调用该对象的`Execute()`方法。那么接下来就是分析`NewCommand()`函数了。  

```go   
// fabric-ca/cmd/fabric-ca-server/servercmd.go

// ServerCmd encapsulates cobra command that provides command line interface
// for the Fabric CA server and the configuration used by the Fabric CA server
type ServerCmd struct {
	// name of the fabric-ca-server command (init, start, version)
	name string
	// rootCmd is the cobra command
	rootCmd *cobra.Command
	// My viper instance
	myViper *viper.Viper
	// blockingStart indicates whether to block after starting the server or not
	blockingStart bool
	// cfgFileName is the name of the configuration file
	cfgFileName string
	// homeDirectory is the location of the server's home directory
	homeDirectory string
	// serverCfg is the server's configuration
	cfg *lib.ServerConfig
}

// NewCommand returns new ServerCmd ready for running
func NewCommand(name string, blockingStart bool) *ServerCmd {
	s := &ServerCmd{
		name:          name,
		blockingStart: blockingStart,
		myViper:       viper.New(),
	}
	s.init()
	return s
}
```  

可以看到，在`NewCommand()`函数中只有三个操作：构造一个`*ServerCmd`的对象、调用它的`init()`函数，然后返回该对象。  

在`*ServerCmd.init()`函数中：  

```go  
// fabric-ca/cmd/fabric-ca-server/servercmd.go

// init initializes the ServerCmd instance
// It intializes the cobra root and sub commands and
// registers command flgs with viper
func (s *ServerCmd) init() {
	// root command
	rootCmd := &cobra.Command{
		Use:   cmdName,
		Short: longName,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := s.configInit()
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			util.CmdRunBegin(s.myViper)
			return nil
		},
	}
	s.rootCmd = rootCmd

	// initCmd represents the server init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: fmt.Sprintf("Initialize the %s", shortName),
		Long:  "Generate the key material needed by the server if it doesn't already exist",
	}
	initCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errors.Errorf(extraArgsError, args, initCmd.UsageString())
		}
		err := s.getServer().Init(false)
		if err != nil {
			util.Fatal("Initialization failure: %s", err)
		}
		log.Info("Initialization was successful")
		return nil
	}
	s.rootCmd.AddCommand(initCmd)

	// startCmd represents the server start command
	startCmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Start the %s", shortName),
	}

	startCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errors.Errorf(extraArgsError, args, startCmd.UsageString())
		}
		err := s.getServer().Start()
		if err != nil {
			return err
		}
		return nil
	}
	s.rootCmd.AddCommand(startCmd)

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Prints Fabric CA Server version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(metadata.GetVersionInfo(cmdName))
		},
	}
	s.rootCmd.AddCommand(versionCmd)
	s.registerFlags()
}

// registerFlags registers command flags with viper
func (s *ServerCmd) registerFlags() {
	...
}

// Configuration file is not required for some commands like version
func (s *ServerCmd) configRequired() bool {
	return s.name != version
}

// getServer returns a lib.Server for the init and start commands
func (s *ServerCmd) getServer() *lib.Server {
	return &lib.Server{
		HomeDir:       s.homeDirectory,
		Config:        s.cfg,
		BlockingStart: s.blockingStart,
		CA: lib.CA{
			Config:         &s.cfg.CAcfg,
			ConfigFilePath: s.cfgFileName,
		},
	}
}
```  

在函数中，首先是创建了一个`*cobra.Command`的对象，在该对象中的主要有两个操作：执行配置初始化以及`util.CmdRunBegin()`操作，之后将该对象赋值给`s.rootCmd`；接下来又创建了三个`*cobra.Command`对象：`initCmd`、`startCmd`和`versionCmd`，分别是服务初始化命令、启动命令和获取server版本命令，创建完成后将这三个命令使用`AddCommand()`添加到`s.rootCmd`，随后执行`s.registerFlags()`操作。`registerFlags()`函数中主要是注册一些命令行参数，这里就不细究了。在 `initCmd`和`startCmd`中都用到了`getServer()`函数，该函数返回一个`*libServer`对象：  

```go 
// fabric-ca/lib/server.go

// Server is the fabric-ca server
type Server struct {
	// The home directory for the server.
	HomeDir string
	// BlockingStart determines if Start is blocking.
	// It is non-blocking by default.
	BlockingStart bool
	// The server's configuration
	Config *ServerConfig
	// Metrics are the metrics that the server tracks for API calls.
	Metrics servermetrics.Metrics
	// Operations is responsible for the server's operation information.
	Operations operationsServer
	// CA is the default certificate authority for the server.
	CA
	// metrics for database requests
	dbMetrics *db.Metrics
	// mux is used to server API requests
	mux *gmux.Router
	// listener for this server
	listener net.Listener
	// An error which occurs when serving
	serveError error
	// caMap is a list of CAs by name
	caMap map[string]*CA
	// caConfigMap is a list CA configs by filename
	caConfigMap map[string]*CAConfig
	// levels currently supported by the server
	levels *dbutil.Levels
	wait   chan bool
	mutex  sync.Mutex
}
```  

## initCmd  

在`initCmd`中，调用了`*libServer`对象`Init()`函数，该函数中调用了`init()`函数来执行server的初始化：  

```go  
// init initializses the server leaving the DB open
func (s *Server) init(renew bool) (err error) {
	s.Config.Operations.Metrics = s.Config.Metrics
	s.Operations = operations.NewSystem(s.Config.Operations)
	s.initMetrics()

	serverVersion := metadata.GetVersion()
	err = calog.SetLogLevel(s.Config.LogLevel, s.Config.Debug)
	if err != nil {
		return err
	}
	log.Infof("Server Version: %s", serverVersion)
	s.levels, err = metadata.GetLevels(serverVersion)
	if err != nil {
		return err
	}
	log.Infof("Server Levels: %+v", s.levels)

	s.mux = gmux.NewRouter()
	// Initialize the config
	err = s.initConfig()
	if err != nil {
		return err
	}
	// Initialize the default CA last
	err = s.initDefaultCA(renew)
	if err != nil {
		return err
	}
	// Successful initialization
	return nil
}
```  

在`init()`函数中，首先调用`initMetrics()`函数来初始化一系列的系统参数，之后是`initConfig()`来初始化配置，`initDefaultCA()`来初始化CA信息。  

`initConfig()`函数里面内容很简单，这里就不赘述了。  

`initDefaultCA()`函数中首先调用`initCA()`来创建一个CA，之后再`addCA()`到server中。在`initCA()`中,  

```go  
// fabric-ca/lib/ca.go

// CA represents a certificate authority which signs, issues and revokes certificates
type CA struct {
	// The home directory for the CA
	HomeDir string
	// The CA's configuration
	Config *CAConfig
	// The file path of the config file
	ConfigFilePath string
	// The database handle used to store certificates and optionally
	// the user registry information, unless LDAP it enabled for the
	// user registry function.
	db db.FabricCADB
	// The crypto service provider (BCCSP)
	csp bccsp.BCCSP
	// The certificate DB accessor
	certDBAccessor *CertDBAccessor
	// The user registry
	registry user.Registry
	// The signer used for enrollment
	enrollSigner signer.Signer
	// Idemix issuer
	issuer idemix.Issuer
	// The options to use in verifying a signature in token-based authentication
	verifyOptions *x509.VerifyOptions
	// The attribute manager
	attrMgr *attrmgr.Mgr
	// The tcert manager for this CA
	tcertMgr *tcert.Mgr
	// The key tree
	keyTree *tcert.KeyTree
	// The server hosting this CA
	server *Server
	// DB levels
	levels *dbutil.Levels
	// CA mutex
	mutex sync.Mutex
}

...

func initCA(ca *CA, homeDir string, config *CAConfig, server *Server, renew bool) error {
	ca.HomeDir = homeDir
	ca.Config = config
	ca.server = server

	err := ca.init(renew)
	if err != nil {
		return err
	}
	log.Debug("Initializing Idemix issuer...")
	ca.issuer = idemix.NewIssuer(ca.Config.CA.Name, ca.HomeDir,
		&ca.Config.Idemix, ca.csp, idemix.NewLib())
	err = ca.issuer.Init(renew, ca.db, ca.levels)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed to initialize Idemix issuer for CA '%s'", err.Error()))
	}
	return nil
}
```  

调用`*CA.init()`函数来初始化一个CA服务，之后使用`idemix.NewIssuer()`实例化一个`*CA.issuer`对象:  

```go  
//fabric-ca/lib/server/idemix/issuer.go

type issuer struct {
	name      string
	homeDir   string
	cfg       *Config
	idemixLib Lib
	db        db.FabricCADB
	csp       bccsp.BCCSP
	// The Idemix credential DB accessor
	credDBAccessor CredDBAccessor
	// idemix issuer credential for the CA
	issuerCred IssuerCredential
	// A random number used in generation of Idemix nonces and credentials
	idemixRand    *amcl.RAND
	rc            RevocationAuthority
	nm            NonceManager
	isInitialized bool
	mutex         sync.Mutex
}

// NewIssuer returns an object that implements Issuer interface
func NewIssuer(name, homeDir string, config *Config, csp bccsp.BCCSP, idemixLib Lib) Issuer {
	issuer := issuer{name: name, homeDir: homeDir, cfg: config, csp: csp, idemixLib: idemixLib}
	return &issuer
}

func (i *issuer) Init(renew bool, db db.FabricCADB, levels *dbutil.Levels) error {
	...
}
```  

随后调用`issuer.Init()`函数来初始化idemix证书服务。

## startCmd  

在`startCmd()`命令中，调用了`*lib.Server.Start()`函数：  

```go  
// fabric-ca/lib/server.go

// Start the fabric-ca server
func (s *Server) Start() (err error) {
	log.Infof("Starting server in home directory: %s", s.HomeDir)

	...

	// Register http handlers
	s.registerHandlers()

	log.Debugf("%d CA instance(s) running on server", len(s.caMap))

	// Start operations server
	err = s.startOperationsServer()
	if err != nil {
		return err
	}

	err = s.Operations.RegisterChecker("server", s)
	if err != nil {
		return nil
	}

	// Start listening and serving
	err = s.listenAndServe()
	...

	return nil
}
```  

其中再次调用了`init()`函数，但这次参数为`false`，表明这次不用重新初始化默认的CA服务了。之后调用了`registerHandlers()`函数，用来注册所有提供服务的终端句柄。接着调用`startOperationsServer()`来开启服务：  

```go  
// fabric-ca/lib/server.go

// operationsServer defines the contract required for an operations server
type operationsServer interface {
	metrics.Provider
	Start() error
	Stop() error
	Addr() string
	RegisterChecker(component string, checker healthz.HealthChecker) error
}

func (s *Server) startOperationsServer() error {
	err := s.Operations.Start()
	if err != nil {
		return err
	}

	return nil
}
```

在`startOperationsServer()`中，使用了`operationsServer.Start()`，在`operationsServer`中定义了server提供操作接口。  

之后调用了`operationsServer.RegisterChecker()`接口来检查server的健康状态。随后，调用了`*Server.listenAndServe()`开始监听和提供服务：  

```go  
// fabric-ca/lib/server.go

// Starting listening and serving
func (s *Server) listenAndServe() (err error) {

	...

	if c.TLS.Enabled {
		...

		listener, err = tls.Listen("tcp", addr, config)
		if err != nil {
			return errors.Wrapf(err, "TLS listen failed for %s", addrStr)
		}
	} else {
		addrStr = fmt.Sprintf("http://%s", addr)
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return errors.Wrapf(err, "TCP listen failed for %s", addrStr)
		}
	}
	s.listener = listener
	log.Infof("Listening on %s", addrStr)

	err = s.checkAndEnableProfiling()
	if err != nil {
		s.closeListener()
		return errors.WithMessage(err, "TCP listen for profiling failed")
	}

	// Start serving requests, either blocking or non-blocking
	if s.BlockingStart {
		return s.serve()
	}
	s.wait = make(chan bool)
	go s.serve()

	return nil
}

func (s *Server) serve() error {
	...
}
```  

> 从上面的函数可以看出，Fabric-ca支持**TLS**服务。

在函数中调用`checkAndEnableProfiling()`来检查`FABRIC_CA_SERVER_PROFILE_PORT`是否可用：

```go
// fabric-ca/lib/server.go

// checkAndEnableProfiling checks for FABRIC_CA_SERVER_PROFILE_PORT env variable
// if it is set, starts listening for profiling requests at the port specified
// by the environment variable
func (s *Server) checkAndEnableProfiling() error {
	...
}
```  

最后调用`server()`，启动服务。  

至此，Fabric-ca server端的启动过程就完成了。当然，文章中省略了很多细节，比如服务的初始化过程、默认CA的生成过程、idemix的issuer证书生成过程等等，这些过程就需要各位自行了解了。