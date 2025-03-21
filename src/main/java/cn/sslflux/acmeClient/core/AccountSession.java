package cn.sslflux.acmeClient.core;

import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;

import java.net.URL;
import java.security.KeyPair;

/**
 * @author liuyg
 * @version 1.0
 * @description: ACME账户会话管理
 * @date 2025/3/20 12:38
 */
@Slf4j
public class AccountSession {
    /**
     * 创建新账户
     * @param session ACME会话
     * @param accountKey 账户密钥对
     * @return 创建的Account对象，失败返回null
     */
    public static Account createAccount(Session session, KeyPair accountKey) {
        try {
            return new AccountBuilder()
                    .useKeyPair(accountKey)
                    .agreeToTermsOfService()
                    .create(session);
        } catch (AcmeException ex) {
            log.error("账户创建失败 [Server: {}]", session.getServerUri(), ex);
            return null;
        }
    }

    /**
     * 绑定/登录现有账户
     * @param session ACME会话
     * @param accountKey 账户密钥对
     * @param accountUrl 账户注册URL（必需）
     * @return 账户对象，失败返回null
     */
    public static Account bindAccount(Session session, KeyPair accountKey, URL accountUrl) {
        try {
            Login login = new Login(accountUrl, accountKey, session);
            return login.getAccount();
        } catch (Exception ex) {
            log.error("账户绑定失败 [URL: {}]", accountUrl, ex);
            return null;
        }
    }


}
