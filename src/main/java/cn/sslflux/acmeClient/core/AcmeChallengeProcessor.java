package cn.sslflux.acmeClient.core;

import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * @author liuyg
 * @version 1.0
 * @description: ACME 挑战处理器
 * @date 2025/3/20 13:46
 */
@Slf4j
@Component
public class AcmeChallengeProcessor {

    private final DnsProvider dnsProvider;

    // 通过构造函数注入DNS挑战处理器
    public AcmeChallengeProcessor(DnsProvider dnsProvider) {
        this.dnsProvider = dnsProvider;
    }

    private static final int MAX_RETRIES = 5;
    private static final Duration RETRY_INTERVAL = Duration.ofSeconds(10);

    /**
     * 处理域名授权挑战
     *
     * @param authorization 授权对象
     * @param preferredType 优先挑战类型
     * @return 是否验证成功
     */
    public boolean processAuthorization(Authorization authorization, String preferredType) {
        try {
            Challenge challenge = selectChallenge(authorization, preferredType);
            if (challenge == null) {
                log.error("没有支持的挑战类型 [Domain: {}]",
                        authorization.getIdentifier().getDomain());
                return false;
            }

            ChallengeHandler handler = createHandler(authorization, challenge);
            return handleChallenge(challenge, handler);
        } catch (Exception ex) {
            log.error("挑战处理失败 [Domain: {}]",
                    authorization.getIdentifier().getDomain(), ex);
            return false;
        }
    }

    /**
     * 选择最佳挑战类型
     */
    private Challenge selectChallenge(Authorization auth, String preferredType) {
        // 优先选择指定类型
        if (preferredType != null) {
            Optional<Challenge> preferred = auth.findChallenge(preferredType);
            if (preferred.isPresent()) {
                return preferred.get();
            }
        }

        // 自动选择支持的挑战类型
        List<String> supportedTypes = Arrays.asList(
                Http01Challenge.TYPE,
                Dns01Challenge.TYPE
        );

        return auth.findChallenge(Dns01Challenge.TYPE)
                .filter(c -> supportedTypes.contains(c.getType()))
                .orElse(null);
    }

    /**
     * 创建对应的挑战处理器
     */
    private ChallengeHandler createHandler(Authorization auth, Challenge challenge) {
        switch (challenge.getType()) {
            case Http01Challenge.TYPE:
                return new Http01Handler((Http01Challenge) challenge);
            case Dns01Challenge.TYPE:
                return new Dns01Handler(auth, (Dns01Challenge) challenge, dnsProvider);
            default:
                throw new UnsupportedOperationException("不支持的挑战类型: " + challenge.getType());
        }
    }

    /**
     * 执行挑战验证流程
     */
    private boolean handleChallenge(Challenge challenge, ChallengeHandler handler) {
        try {

            // 状态预检查
            challenge.update(); // 首次刷新状态
            if (challenge.getStatus() != Status.PENDING) {
                log.warn("挑战状态异常，当前状态: {} [Type: {}]",
                        challenge.getStatus(), challenge.getType());
                return challenge.getStatus() == Status.VALID; // 如果已经是VALID则直接返回成功
            }

            handler.prepare();

            // 触发前等待（建议）
            try {
                Thread.sleep(3000L); // 等待DNS/HTTP配置生效
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
            challenge.trigger();

            // 改进的重试机制（增加指数退避）
            int attempts = 0;
            long delay = RETRY_INTERVAL.toMillis();
            while (attempts++ < MAX_RETRIES) {
                try {
                    challenge.update(); // 每次循环必须刷新状态
                    Status status = challenge.getStatus();

                    if (status == Status.VALID) {
                        log.info("挑战验证成功 [Type: {}]", challenge.getType());
                        return true;
                    }

                    if (status == Status.INVALID) {
                        log.error("挑战验证失败 [Error: {}]", challenge.getError());
                        return false;
                    }

                    // 改进的等待策略（指数退避）
                    long sleepTime = (long) (delay * Math.pow(1.5, attempts));
                    log.debug("等待挑战验证 ({}/{}), 下次等待: {}ms...",
                            attempts, MAX_RETRIES, sleepTime);
                    Thread.sleep(sleepTime);

                } catch (AcmeException ex) {
                    log.warn("挑战状态检查失败（{}）", ex.getMessage());
                }
            }

            log.error("挑战验证超时");
            return false;
        } catch (Exception e) {
            throw new RuntimeException("挑战处理异常", e);
        } finally {
            handler.cleanup();
        }
    }

    /**
     * 挑战处理器接口
     */
    public interface ChallengeHandler {
        void prepare() throws Exception;

        void cleanup();
    }

    /**
     * HTTP-01 挑战处理器
     */
    public static class Http01Handler implements ChallengeHandler {
        private final Http01Challenge challenge;
        private final String token;
        private final String content;

        public Http01Handler(Http01Challenge challenge) {
            this.challenge = challenge;
            this.token = challenge.getToken();
            this.content = challenge.getAuthorization();
        }

        @Override
        public void prepare() throws Exception {
            Path path = Paths.get("/var/www/.well-known/acme-challenge/", token);
            Files.createDirectories(path.getParent());
            Files.writeString(path, content);
            log.debug("HTTP挑战文件已部署: {}", path);
        }

        @Override
        public void cleanup() {
            try {
                Path path = Paths.get("/var/www/.well-known/acme-challenge/", token);
                Files.deleteIfExists(path);
            } catch (IOException ex) {
                log.warn("清理HTTP挑战文件失败", ex);
            }
        }
    }

    /**
     * DNS-01 挑战处理器
     */
    public static class Dns01Handler implements ChallengeHandler {
        private final Dns01Challenge challenge;
        private final String recordName;
        private final String recordValue;
        private final DnsProvider dnsProvider;
        private final Authorization auth;

        public Dns01Handler(Authorization auth, Dns01Challenge challenge, DnsProvider dnsProvider) {
            this.auth = Objects.requireNonNull(auth);
            this.challenge = Objects.requireNonNull(challenge);
            this.dnsProvider = Objects.requireNonNull(dnsProvider);
            Identifier identifier = auth.getIdentifier();
            this.recordName = "_acme-challenge." + identifier.getDomain();
            this.recordValue = challenge.getDigest();
        }

        @Override
        public void prepare() throws Exception {
            dnsProvider.addTxtRecord(recordName, recordValue);
            log.debug("DNS记录已添加: {}={}", recordName, recordValue);
        }

        @Override
        public void cleanup() {
            try {
                dnsProvider.removeTxtRecord(recordName);
            } catch (Exception ex) {
                log.warn("清理DNS记录失败", ex);
            }
        }
    }


}
