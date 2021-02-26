<h1 align="center">
  <br>
  Hyperledger Fabric CA 国密版
  <br>
  <p align="center">
    <a href="https://ci.blockchain.thoughtworks.cn/blue/organizations/jenkins/fabric-gm%2Ffabric-ca/activity/">
      <img src="https://ci.blockchain.thoughtworks.cn/buildStatus/icon?job=fabric-gm%2Ffabric-ca" alt="Build Status">
    </a>
    <img src="https://img.shields.io/badge/contributions-welcome-orange.svg" alt="Contributions welcome">
    <img src="https://img.shields.io/badge/Fabric-1.4-blue" alt="Fabric 1.4">
    <img src="https://img.shields.io/badge/GM-enable-green" alt="gm tls enable">
  </p>
</h1>
<h4 align="center">本项目是 Hyperledger Fabric CA 的国密支持版本。</h4>

## 简介

本项目是Hyperledger Fabric国密化的关联项目，访问 [Hyperledger Fabric国密版](https://github.com/tw-bc-group/fabric) 了解更多。

### 本项目的优势
本项目涵盖 Fabric、Fabric CA 以及 Fabric SDK 的全链路国密改造，主要包括以下功能点：
* 国密 CA 生成和签发
* 应用数据国密加密/签名/解密
* 国密 TLS 的 GRPCS 和 HTTPS 通讯
* 国密加密机/协同运算集成

### 什么是Hyperledger Fabric？
Hyperledger Fabric是用于开发解决方案和应用程序的企业级许可分布式分类账本框架，可以去[官网](https://www.hyperledger.org/use/fabric)了解更多。

### 什么是国密(GM)？
国密(GM)算法是[国家密码管理局](https://www.oscca.gov.cn/)发布的、符合[《密码法》](http://www.npc.gov.cn/npc/c30834/201910/6f7be7dd5ae5459a8de8baf36296bc74.shtml)中规定的商用密码的一套密码标准规范。

## 依赖与关联

### 依赖
* Fabric 版本：[1.4](https://github.com/hyperledger/fabric/tree/release-1.4)
* 国密实现库：[基于同济 Golang 国密实现库](https://github.com/Hyperledger-TWGC/tjfoc-gm)

### 关联代码库
本代码库为 Fabric-CA 的国密化版本，Fabric 的其他部分国密化改造如下：
* [国密化 Fabric Core](https://github.com/tw-bc-group/fabric)
* [国密化 Samples](https://github.com/tw-bc-group/fabric-samples)
* [国密化 SDK](https://github.com/tw-bc-group/fabric-sdk-go)

## 如何使用
与官方 Fabric CA 1.4 一致，参考[ Fabric CA 官方文档](https://hyperledger-fabric-ca.readthedocs.io/en/release-1.4/)。

### 常用命令
* `make native`进行编译
* `make docker`打包docker镜像

### 使用镜像

本项目使用 [CI](https://ci.blockchain.thoughtworks.cn/blue/organizations/jenkins/fabric-gm%2Ffabric-ca/activity/) 持续编译并测试，并将镜像发表在dockerhub，可使用镜像：

* [twblockchain/fabric-ca](https://hub.docker.com/r/twblockchain/fabric-ca)

### 欢迎反馈
欢迎各种反馈～ 你可以在 [issues页面](https://github.com/tw-bc-group/fabric-gm/issues) 提交反馈，我们收到后会尽快处理。

### 如何贡献
欢迎通过以下方式贡献本项目：

* 提带有 label 的 issue
* 提出任何期望的功能、改进
* 提交 bug
* 修复 bug
* 参与讨论并帮助决策
* 提交 Pull Request

## 关于我们
国密化改造工作主要由 ThoughtWorks 区块链团队完成，想要了解更多/商业合作/联系我们，欢迎访问我们的[官网](https://blockchain.thoughtworks.cn/)。
