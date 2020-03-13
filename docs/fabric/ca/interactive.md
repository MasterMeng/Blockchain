# Fabric-ca server端与client端交互  

本文介绍Fabric-ca server端和client端的交互过程。  

在server端执行`Start()`命令时，会调用`registerHandlers()`函数，其作用就是注册处理客户端请求的程序：  

```go
// fabric-ca/lib/server.go

// Register all endpoint handlers
func (s *Server) registerHandlers() {
	s.mux.Use(s.cors, s.middleware)
	s.registerHandler(newCAInfoEndpoint(s))
	s.registerHandler(newRegisterEndpoint(s))
	s.registerHandler(newEnrollEndpoint(s))
	s.registerHandler(newIdemixEnrollEndpoint(s))
	s.registerHandler(newIdemixCRIEndpoint(s))
	s.registerHandler(newReenrollEndpoint(s))
	s.registerHandler(newRevokeEndpoint(s))
	s.registerHandler(newTCertEndpoint(s))
	s.registerHandler(newGenCRLEndpoint(s))
	s.registerHandler(newIdentitiesStreamingEndpoint(s))
	s.registerHandler(newIdentitiesEndpoint(s))
	s.registerHandler(newAffiliationsStreamingEndpoint(s))
	s.registerHandler(newAffiliationsEndpoint(s))
	s.registerHandler(newCertificateEndpoint(s))
}

// Register a handler
func (s *Server) registerHandler(se *serverEndpoint) {
	s.mux.Handle("/"+se.Path, se).Name(se.Path)
	s.mux.Handle(apiPathPrefix+se.Path, se).Name(se.Path)
}
```  

这里以`newCAInfoEndpoint()`为例来介绍server端与client端的交互过程。  

```go
// fabric-ca/lib/serverinfo.go

// ServerInfoResponseNet is the response to the GET /cainfo request
type ServerInfoResponseNet struct {
	// CAName is a unique name associated with fabric-ca-server's CA
	CAName string
	// Base64 encoding of PEM-encoded certificate chain
	CAChain string
	// Base64 encoding of idemix issuer public key
	IssuerPublicKey string
	// Version of the server
	Version string
}

func newCAInfoEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Path:    "cainfo",
		Methods: []string{"GET", "POST", "HEAD"},
		Handler: cainfoHandler,
		Server:  s,
	}
}

// Handle is the handler for the GET or POST /cainfo request
func cainfoHandler(ctx *serverRequestContextImpl) (interface{}, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	resp := &common.CAInfoResponseNet{}
	err = ca.fillCAInfo(resp)
	if err != nil {
		return nil, err
	}
	resp.Version = metadata.GetVersion()
	return resp, nil
}
```  

> Note：假设server的IP为“192.168.1.20”，端口为“8888”

从上面的代码不难看出，server端对于URL为*http://192.168.1.20:8888/cainfo*，提供三种方法，分别为**GET**、**POST**和**HEAD**。本文中为**GET**方法为例。  

此时，client端需要执行的命令就是`newGetCAInfoCmd().getCommand()`，在`runGetCACert()`函数中，会构造一个`api.GetCAInfoRequest`结构，通过`lib.Client.GetCAInfo()`函数来发送请求并接受server端的响应。  

```go
// fabric-ca/cmd/fabric-ca-client/command/getcainfo.go

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
```  

server端收到请求后，调用`newCAInfoEndpoint()`方法处理请求。在`newCAInfoEndpoint()`中会调用`cainfoHandler()`函数，该函数才是处理程序的本体。  

在`cainfoHandler()`中，首先会调用`serverRequestContextImpl.GetCA()`来获取server端CA的信息，并将获取到的信息存入到`CA`结构体中，之后构造一个`common.CAInfoResponseNet{}`结构体，随后调用`CA`的`fillCAInfo()`方法将CA信息填充到结构体中，返回响应信息。  

```go
// fabric-ca/lib/common/serversponses.go

// CAInfoResponseNet is the response to the GET /info request
type CAInfoResponseNet struct {
	// CAName is a unique name associated with fabric-ca-server's CA
	CAName string
	// Base64 encoding of PEM-encoded certificate chain
	CAChain string
	// Base64 encoding of Idemix issuer public key
	IssuerPublicKey string
	// Base64 encoding of PEM-encoded Idemix issuer revocation public key
	IssuerRevocationPublicKey string
	// Version of the server
	Version string
}
```