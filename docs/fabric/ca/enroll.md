# fabric-ca-client enroll过程分析  

在fabric-ca-client中，提供如下命令：  

- **affiliation**：管理从属关系
- **certificate**：管理证书
- **enroll**：登记身份
- **gencrl**：生成CRL（Certificate Revolution List）
- **gencsr**：生成CSR（Certificate Signing Request）
- **getcainfo**：获取CA证书链及Idemix公约
- **identi**：管理身份
- **reenroll**：重新登记身份
- **register**：注册身份
- **revoke**：撤销身份
- **version**：输出Fabric CA Client版本号  

本文以*enroll*为例，从源码着手，分析fabric-ca-client与fabric-ca-server端的交互过程。  

## 开始之前  

依照[这里](https://hyperledger-fabric-ca.readthedocs.io/en/release-1.4/index.html)的说明文档，使用从[github](https://github.com/hyperledger/fabric-ca/releases)获取的可执行程序执行**server start**和**client enroll**操作。  

启动**server**：

> fabric-ca-server init -b admin:adminpw

之后会在当前目录下生成一些必要的文件，包括：  

- IssuerPublicKey：颁发者的公钥
- IssuerRevocationPublicKey：颁发的撤销公钥
- ca-cert.pem：CA的根证书
- fabric-ca-server-config.yaml：server端的配置
- fabric-ca-server.db：sqlite3数据库，存放数据
- msp：用于存放server端的私钥文件

启动：

> fabric-ca-server start -b admin:adminpw
  

client执行：  

```bash
export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/clients/admin
fabric-ca-client enroll -u http://admin:adminpw@localhost:7054
```  

执行结束之后会在`$HOME/fabric-ca/clients/admin`目录下生成：

- fabric-ca-client-config.yaml：client端配置
- msp：存放client端秘钥信息及证书凭证  

## 开始  

Fabric-ca中采用[Cobra](https://github.com/spf13/cobra)来提供命令行服务。在使用者输入**enroll**时，对应的会调用`fabric-ca/cmd/fabric-ca-client/enroll.go`中的命令。在`enroll.go`中，包含：  

- **newEnrollCmd()**：构造一个`enrollCmd`实例并返回。
- **getCommand()**：返回`*cobra.Command`实例，其中包含两个命令：  
  - **preRunEnroll()**：预处理命令，负责初始化`runEnroll()`执行时的相关配置。
  - **runEnroll()**：`newEnrollCmd()`命令的核心内容，负责向服务端发送`enroll`请求，并将返回的身份信息进行存储。  

---  

## Client  

```go

func (c *enrollCmd) runEnroll(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runEnroll")
	cfgFileName := c.GetCfgFileName()
	cfg := c.GetClientCfg()
	resp, err := cfg.Enroll(cfg.URL, filepath.Dir(cfgFileName))
	if err != nil {
		return err
	}

	......
}

```

在`runEnroll()`命令中：  

- 首先`GetCfgFileName()`获取配置文件，之后通过`c.GetClientCfg()`来获取客户端的配置，其类型为`*lib.ClientConfig`，之后调用`*lib.ClientConfig`的`Enroll()`接口来发送Enroll请求。  
- 在`*lib.ClientConfig.Enroll()`中，首先从参数`rawurl`中解析出用户名跟密码，实例化`ClientConfig`结构体中的`Enrollment`成员变量，其数据类型为`api.EnrollmentRequest`，该类型中包含登记身份所有需要的所有信息。随后构造出一个`Client`的实例，调用它的`Enroll()`函数来，发送请求。
- 在`Clinet.Enroll()`中，首先`Init()`初始化参数，之后根据`*api.EnrollmentRequest.Type`的值来判断是要获取**X509**格式的证书还是**idemix**格式的。这里以**idemix**为例，调用`handleIdemixEnroll()`函数：  
  - 在`handleIdemixEnroll()`，首先构造出一个类型为`api.IdemixEnrollmentRequestNet`的实例，其中包含CA名称和`idemix.CredRequest`，
  - 之后向server的`idemix/credential`地址发送**Post**，此时`api.IdemixEnrollmentRequestNet.CredRequest`为空，server端会返回一个`EnrollmentResponse`类型的消息，并为其中`Nonce`字段赋值。
  - client接收到返回的消息后，从中解析出`Nonce`，然后通过`newIdemixCredentialRequest()`函数调用`idemix.NewCredRequest()`，生成idemix.CredRequest和私钥。
  - 将生成的idemix.CredRequest赋值给之前生成`api.IdemixEnrollmentRequestNet`的实例，随后再向server的`idemix/credential`地址发送**Post**。此次server端返回的`EnrollmentResponse`中将包含生成的idemix证书。
  - 最后调用`newIdemixEnrollmentResponse()`，解析返回的`EnrollmentResponse`，构建client端的`EnrollmentResponse`实例并返回结果。

```go
func (c *enrollCmd) runEnroll(cmd *cobra.Command, args []string) error {
	......
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

在接收到`cfg.Enroll()`的返回之后：  

- 生成该用户身份的配置文件。
- 存储身份凭证
- 存储CA链
- 存储Issuer公钥
- 存储Issuer的撤销公钥

## Server  

在client端发送的`idemix/credential`请求的处理函数位于`fabric-ca/lib/srveridemixenroll.go`中，使用`handleIdemixEnrollReq()`来处理请求：  

- 首先调用`Issuer.IssueCredential`接口，处理请求，并返回`EnrollmentResponse`的实例
- 之后调用`newIdemixEnrollmentResponseNet()`来生成一个`common.IdemixEnrollmentResponseNet`实例并返回，其中不仅包含`EnrollmentResponse`，还包含CA的信息

在client端的一次`enroll`命令中，server端会调用`handleIdemixEnrollReq()`两次：第一次生成client端生成idemix.CredRequest时需要的Nonce，第二次根据client端发过来的请求来生成idemix证书。