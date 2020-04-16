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

