# Fabric中的idemix  

Idemix是fabric中的零知识证明的实现，用户在无需暴露私有数据以及任何有用信息的基础上，向验证者证明自己拥有这些私有数据。  

## Idemix的特性  

与X.509证书相比：  

* 相同点：  
  * 一组属性被签名，且签名不可伪造
  * 凭证通过密码学的方式绑定到一个秘钥
* 不同点：  
  * idemix通过零知识证明来验证身份，验证过程中不会泄露知识或信息；X.509通过申请的证书来验证身份，证书是公开的
  * 用户通过idemix凭证验证的交易，各交易之间是无关联的，且不可回溯；而X.509证书中所有的信息都是公开的，通过X.509验证的交易，跟用户的身份是绑定的  

## Idemix局限性  

* 只支持固定的属性，例如OU(OrganizationalUnitIdentifier)、Role、Enrollment ID、Revocation Handle attribute等
* 不支持idemix凭证撤销
* Peer不支持使用idemix来进行背书，只能用来验证签名，且idemix签名只能通过SDK来进行
* idemix当前仅提供同一组织中的client匿名性