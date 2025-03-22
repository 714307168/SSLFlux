```markdown
# SSLFlux - 自动化SSL证书管理平台

> 基于Java实现的SSL证书全生命周期管理工具，支持Let's Encrypt证书自动化申请与多平台CDN部署

## 🌟 核心特性

- **全自动证书管理**
  - 自动申请/续期Let's Encrypt证书（支持HTTP-01/DNS-01验证）
  - 智能监控证书有效期（提前30天预警）
  
- **多云CDN支持**
- 准备实现：阿里云CDN、腾讯云CDN
- 扩展接口：开发者可快速对接新平台

- **企业级安全设计**
    - 密钥加密存储
    - 证书隔离策略（开发/生产环境分离）

## 🛠️ 技术架构

### 核心组件
```bash
src/main/java/cn/sslflux
├── acmeClient        # ACME协议实现
├── cloudAdapters     # 云厂商适配器
├── certManager       # 证书存储管理
└── scheduler         # 定时任务调度

certs 生成的证书会在这个目录下
acme_account.properties 首次运行会生成这个文件，保存acme登录账号
```

### 技术栈
| 组件              | 技术选型                   |
|-------------------|------------------------|
| 开发框架          | Spring Boot 3.0.4      |
| ACME协议实现      | acme4j 3.5.1            | 
| 云服务SDK         | 阿里云SDK for Java |
| 安全存储          | BouncyCastle + JCA     |
| 任务调度          | Quartz Scheduler       |

## 🚀 快速开始

### 环境要求
- JDK 17+
- Maven 3.6+
- Let's Encrypt账户

### 安装步骤
1. 克隆仓库
```bash
git clone https://github.com/714307168/SSLFlux.git
```

2. 配置云厂商凭证
```yaml
# application.yml
certjet:
  cloud:
    aliyun:
      access-key: AK_xxxx
      secret-key: SK_yyyy
acme:
  serverUri: https://acme-v02.api.letsencrypt.org/directory
  keystore:
    # Windows路径
    file: file:D:/sslcret/keystore.p12
    # Linux/macOS路径
    # file: file:/home/user/sslcret/keystore.p12
    password: mySecurePassword123
  contact:
    email: 12345678@qq.com
```

3. 启动服务
```bash
java -jar certjet.jar
```

## 🔧 配置说明

### 主要配置项
| 参数                      | 说明                     | 示例值          |
|---------------------------|--------------------------|--------------|
| certjet.domains           | 需要管理的域名列表        | www.liuyg.cn |
| certjet.acme.environment  | ACME环境(staging/prod)   | staging      |
| certjet.storage.type      | 证书存储方式(local/hsm)  | local        |

## 📌 开发路线图

### v1.0-MVP
- ✅ Let's Encrypt、Google Trust Services证书自动化申请
- ✅ 阿里云CDN适配
- ✅ 多证书存储策略（本地/OSS）
- [ ] 腾讯云CDN适配

### v2.0-企业版
- [ ] 可视化监控面板
- [ ] 基于角色的访问控制(RBAC)
- [ ] 证书吊销管理

## 📄 开源协议
Apache License 2.0 - 详情见 [LICENSE](LICENSE)


## Star 趋势图
[![Star 趋势图](https://starchart.cc/714307168/SSLFlux.svg?variant=adaptive)](https://starchart.cc/714307168/SSLFlux)