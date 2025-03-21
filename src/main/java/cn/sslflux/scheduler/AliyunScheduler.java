package cn.sslflux.scheduler;

import cn.sslflux.Utils.CertUtils;
import cn.sslflux.Utils.DomainUtils;
import cn.sslflux.acmeClient.core.AccountSession;
import cn.sslflux.acmeClient.core.AcmeChallengeProcessor;
import cn.sslflux.acmeClient.core.AcmeCoreClient;
import cn.sslflux.acmeClient.core.DnsProvider;
import cn.sslflux.acmeClient.model.CertificateValidityPeriod;
import cn.sslflux.cloudAdapters.AliyunCDN;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

/**
 * @author liuyg
 * @version 1.0
 * @description: 阿里云 证书自动续期
 * @date 2025/3/21 12:28
 */
@Slf4j
@Component
public class AliyunScheduler {
    @Autowired
    private AliyunCDN aliyunCDN;

    @Autowired
    private AcmeChallengeProcessor challengeProcessor;

    @Autowired
    private DnsProvider aliDnsProvider;

    @Autowired
    private AccountSession accountSession;

    // 每天凌晨1点执行
    @Scheduled(cron = "0 0 1 * * ?")
    @PostConstruct
    public void autoRenewCertificates() {
        List<CertificateValidityPeriod> domains = aliyunCDN.getDomainList();
        domains.forEach(this::processDomainCertificate);
    }

    private void processDomainCertificate(CertificateValidityPeriod domainCert) {
        try {
            if (domainCert.getNotAfter() == null) {
                log.info("检测到域名没有证书 [Domain: {}] ",
                        domainCert.getHostname());
                renewCertificate(domainCert.getHostname());
            } else if (isCertExpiringSoon(domainCert.getNotAfter())) {
                log.info("检测到证书即将过期 [Domain: {}] [Expire: {}]",
                        domainCert.getHostname(), domainCert.getNotAfter());
                renewCertificate(domainCert.getHostname());
            }
        } catch (Exception ex) {
            log.error("证书续期处理失败 [Domain: {}]", domainCert.getHostname(), ex);
        }
    }

    private boolean isCertExpiringSoon(Date expireDate) {
        Instant expireInstant = expireDate.toInstant();
        return Instant.now().plus(15, ChronoUnit.DAYS).isAfter(expireInstant);
    }

    private void renewCertificate(String domain) {
        try {
            // 创建或绑定账户
            Account account = accountSession.initializeAccount();
            if (account == null) {
                throw new IllegalStateException("ACME账户创建失败");
            }
            // 创建核心客户端
            AcmeCoreClient client = new AcmeCoreClient(account);
            // 创建证书订单
            if (domain.startsWith(".")) {
                domain = DomainUtils.extractRootDomain(domain);
            }
            Order order = client.createOrder(List.of(domain), 90);
            if (order == null) return;
            // 处理授权挑战
            boolean authSuccess = challengeProcessor.processAuthorization(
                    order.getAuthorizations().get(0),
                    Dns01Challenge.TYPE
            );
            if (authSuccess) {
                // 生成域名密钥对
                KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048);

                // 完成订单获取证书
                Certificate certificate = client.finalizeOrder(order, domainKeyPair);
                // 新增证书保存逻辑
                if (certificate != null) {
                    saveCertificateToFile(domain, certificate, domainKeyPair); // 新增保存方法
                    deployToAliyunCDN(domain, certificate, domainKeyPair);
                }
            }
        } catch (Exception ex) {
            log.error("证书续期流程异常 [Domain: {}]", domain, ex);
        }
    }

    /**
     * @description: 证书保存方法
     * @author liuyg
     * @date 2025/3/21 21:56
     * @version 1.0
     */
    private void saveCertificateToFile(String domain, Certificate certificate, KeyPair keyPair) {
        try {
            // 1. 创建证书保存目录
            Path certsDir = Paths.get("certs");
            if (!Files.exists(certsDir)) {
                Files.createDirectories(certsDir);
            }

            // 2. 生成文件名（含时间戳防重复）
            String timestamp = Instant.now().toString().replace(":", "-");
            String baseName = domain + "_" + timestamp;

            // 3. 保存证书链
            String certPem = CertUtils.generateFullChainPem(certificate.getCertificateChain());
            Files.write(certsDir.resolve(baseName + "_cert.pem"), certPem.getBytes());

            // 4. 保存私钥
            String keyPem = CertUtils.generatePrivateKeyPem(keyPair.getPrivate());
            Files.write(certsDir.resolve(baseName + "_key.pem"), keyPem.getBytes());

            log.info("证书已保存到本地目录 [Path: {}]", certsDir.toAbsolutePath());
        } catch (Exception ex) {
            log.error("证书保存失败 [Domain: {}]", domain, ex);
        }
    }

    private void deployToAliyunCDN(String domain, Certificate certificate, KeyPair keyPair) {
        try {
            // 获取证书链列表
            List<X509Certificate> certChain = certificate.getCertificateChain();
            if (certChain == null || certChain.isEmpty()) {
                throw new IllegalStateException("证书链为空");
            }
            // 生成完整证书链PEM格式
            String certPem = CertUtils.generateFullChainPem(certChain);
            // 生成私钥PEM格式
            String keyPem = CertUtils.generatePrivateKeyPem(keyPair.getPrivate());
            // 验证公私钥匹配性（新增验证）
//            if (!CertUtils.validateKeyPair(certPem, keyPem)) {
//                log.error("证书与私钥不匹配 [Domain: {}]", domain);
//                return;
//            }
            // 生成唯一证书名称
            String certName = "sslflux-cert-" + System.currentTimeMillis();
//             调用阿里云CDN API更新证书
            boolean success = aliyunCDN.setCdnDomainSSLCertificate(domain, certName, certPem, keyPem);
//             此处需要实现具体上传逻辑
            if (success) {
                log.info("证书已更新到阿里云CDN [Domain: {}] [CertName: {}]", domain, certName);
            } else {
                log.error("证书上传失败 [Domain: {}]", domain);
            }
        } catch (Exception ex) {
            log.error("证书部署到CDN失败 [Domain: {}]", domain, ex);
        }
    }
}
