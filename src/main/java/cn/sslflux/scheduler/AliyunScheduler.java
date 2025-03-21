package cn.sslflux.scheduler;

import cn.sslflux.Utils.Base64Utils;
import cn.sslflux.Utils.DomainUtils;
import cn.sslflux.acmeClient.core.AccountSession;
import cn.sslflux.acmeClient.core.AcmeChallengeProcessor;
import cn.sslflux.acmeClient.core.AcmeCoreClient;
import cn.sslflux.acmeClient.core.DnsProvider;
import cn.sslflux.acmeClient.model.AcmeConfig;
import cn.sslflux.acmeClient.model.CertificateValidityPeriod;
import cn.sslflux.cloudAdapters.AliyunCDN;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
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
    private AcmeConfig acmeConfig;

    @Autowired
    private AcmeChallengeProcessor challengeProcessor;

    @Autowired
    private DnsProvider aliDnsProvider;

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
            // 初始化ACME会话
            Session session = new Session(acmeConfig.getServerUri());
            KeyPair accountKey = KeyPairUtils.createKeyPair(2048);

            // 创建或绑定账户
            Account account = AccountSession.getOrCreateAccount(session, accountKey);
            if (account == null) {
                throw new IllegalStateException("ACME账户创建失败");
            }

            // 创建核心客户端
            AcmeCoreClient client = new AcmeCoreClient(account);
            // 创建证书订单
            if (domain.startsWith(".")) {
                domain = DomainUtils.extractRootDomain(domain);
            }
            Order order = client.createOrder(List.of(domain), 89);
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
                if (certificate != null) {
                    deployToAliyunCDN(domain, certificate, domainKeyPair);
                }
            }
        } catch (Exception ex) {
            log.error("证书续期流程异常 [Domain: {}]", domain, ex);
        }
    }

    private void deployToAliyunCDN(String domain, Certificate certificate, KeyPair keyPair) {
        try {
            // 获取证书链列表
            List<X509Certificate> certChain = certificate.getCertificateChain();
            if (certChain == null || certChain.isEmpty()) {
                throw new IllegalStateException("证书链为空");
            }

            // 将证书链转换为PEM格式字节数组
            ByteArrayOutputStream certChainBytes = new ByteArrayOutputStream();
            for (X509Certificate cert : certChain) {
                certChainBytes.write("-----BEGIN CERTIFICATE-----\n".getBytes());
                certChainBytes.write(Base64Utils.encodeToString(cert.getEncoded()).getBytes());
                certChainBytes.write("\n-----END CERTIFICATE-----\n".getBytes());
            }
            // 获取终端实体证书（第一个证书）
            X509Certificate x509Cert = certChain.get(0);
            log.info("证书解析成功 [Subject: {}]", x509Cert.getSubjectX500Principal());
            // 将证书和私钥转换为Base64字符串
            // 将证书和私钥转换为Base64字符串
            String certString = Base64Utils.encodeToString(certChainBytes.toByteArray());
            String privateKeyString = Base64Utils.encodeToString(keyPair.getPrivate().getEncoded());
//             调用阿里云CDN API更新证书
            aliyunCDN.setCdnDomainSSLCertificate(domain, "sslflux-" + x509Cert.getSerialNumber(), certString, privateKeyString);
//             此处需要实现具体上传逻辑
            log.info("证书已更新到阿里云CDN [Domain: {}] [Serial: {}]",
                    domain, x509Cert.getSerialNumber());
        } catch (Exception ex) {
            log.error("证书部署到CDN失败 [Domain: {}]", domain, ex);
        }
    }
}
