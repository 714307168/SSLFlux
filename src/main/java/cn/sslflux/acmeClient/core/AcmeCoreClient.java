package cn.sslflux.acmeClient.core;

import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.util.CSRBuilder;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * @author liuyg
 * @version 1.0
 * @description: Acme核心客户端
 * @date 2025/3/20 12:03
 */
@Slf4j
public class AcmeCoreClient {

    private final Account account;

    public AcmeCoreClient(Account account) {
        this.account = account;
    }

    /**
     * 创建新的证书订单
     *
     * @param domains      域名列表 (至少一个)
     * @param validityDays 证书有效期天数 (可选)
     * @return Order 对象，失败返回 null
     */
    public Order createOrder(List<String> domains, Integer validityDays) {
        try {
            OrderBuilder orderBuilder = account.newOrder()
                    .domains(domains.toArray(new String[0]));

            // 带有效期参数的创建尝试
            if (validityDays != null && validityDays > 0) {
                try {
                    orderBuilder.notAfter(Instant.now().plus(Duration.ofDays(validityDays)));
                    return orderBuilder.create();
                } catch (AcmeServerException ex) {
                    if (ex.getMessage().contains("NotBefore and NotAfter")) {
                        log.warn("CA不支持自定义有效期，回退默认设置");
                        return account.newOrder()  // 重新创建无参数构建器
                                .domains(domains.toArray(new String[0]))
                                .create();
                    }
                    throw ex;  // 其他类型异常继续抛出
                }
            }
            return orderBuilder.create();
        } catch (AcmeException ex) {
            log.error("订单创建失败 [Domains: {}]", domains, ex);
            return null;
        }
    }


    /**
     * 处理订单授权
     *
     * @param order            需要处理的订单
     * @param challengeHandler 挑战处理器接口
     * @return 是否所有授权处理成功
     */
    public boolean processAuthorizations(Order order, ChallengeHandler challengeHandler) {
        boolean allSuccess = true;

        for (Authorization auth : order.getAuthorizations()) {
            try {
                if (auth.getStatus() == Status.PENDING) {
                    log.debug("处理授权: {}", auth.getIdentifier().getDomain());

                    Challenge challenge = selectChallenge(auth);
                    challengeHandler.prepare(challenge);
                    challenge.trigger();
                    challengeHandler.validate(challenge);

                    auth.update();
                    if (auth.getStatus() != Status.VALID) {
                        log.error("授权验证失败: {}", auth.getIdentifier().getDomain());
                        allSuccess = false;
                    }
                }
            } catch (Exception ex) {
                log.error("授权处理异常 [Domain: {}]",
                        auth.getIdentifier().getDomain(), ex);
                allSuccess = false;
            }
        }

        return allSuccess;
    }

    /**
     * 选择挑战类型 (默认选择HTTP-01)
     */
    private Challenge selectChallenge(Authorization auth) {
        return auth.findChallenge(Http01Challenge.TYPE)
                .orElseThrow(() -> new IllegalStateException(
                        "No supported challenge found for domain: " +
                                auth.getIdentifier().getDomain()));
    }

    /**
     * 最终完成订单
     *
     * @param order   已通过验证的订单
     * @param keyPair 域名密钥对
     * @return 签发的证书
     */
    public Certificate finalizeOrder(Order order, KeyPair keyPair) {
        try {
            CSRBuilder csrBuilder = new CSRBuilder();
            List<String> domainList = order.getIdentifiers().stream()
                    .map(identifier -> identifier.getDomain())
                    .toList();
            csrBuilder.addDomains(domainList.toArray(new String[0]));
            csrBuilder.sign(keyPair);
            order.execute(csrBuilder.getEncoded());
            Certificate certificate = order.getCertificate();
            log.info("证书签发成功 [Serial: {}]", certificate.getCertificate().getSerialNumber());
            return certificate;
        } catch (Exception ex) {
            log.error("订单完成失败 [OrderID: {}]", order.getLocation(), ex);
            return null;
        }
    }

    /**
     * 挑战处理器接口
     */
    public interface ChallengeHandler {
        void prepare(Challenge challenge) throws Exception;

        void validate(Challenge challenge) throws Exception;
    }
}
