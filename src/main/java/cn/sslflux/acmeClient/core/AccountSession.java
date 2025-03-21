package cn.sslflux.acmeClient.core;

import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Properties;

/**
 * @author liuyg
 * @version 1.0
 * @description: ACME账户会话管理
 * @date 2025/3/20 12:38
 */
@Slf4j
public class AccountSession {

    private static final String STORE_FILE = "acme_account.properties";
    private static final String KEY_ACCOUNT_URL = "account.url";
    private static final String KEYSTORE_FILE = "keystore.p12";
    private static final String KEYSTORE_PASSWORD = "changeit"; // 生产环境应从安全配置读取

    // 新增方法：获取或创建账户
    public static Account getOrCreateAccount(Session session, KeyPair accountKey) {
        try {
            // 1. 尝试加载已有账户
            Account existingAccount = loadExistingAccount(session, accountKey);
            if (existingAccount != null) {
                log.info("成功加载已存在的ACME账户");
                return existingAccount;
            }

            // 2. 创建新账户
            log.info("创建新的ACME账户...");
            Account newAccount = createAccount(session, accountKey);
            if (newAccount != null) {
                saveAccountInfo(newAccount.getLocation(), accountKey);
            }
            return newAccount;
        } catch (Exception e) {
            log.error("账户初始化失败", e);
            return null;
        }
    }

    // 新增方法：加载已有账户
    private static Account loadExistingAccount(Session session, KeyPair accountKey) {
        try {
            // 1. 从属性文件读取账户URL
            Properties props = new Properties();
            if (!Files.exists(Path.of(STORE_FILE))) {
                return null;
            }

            try (InputStream in = Files.newInputStream(Path.of(STORE_FILE))) {
                props.load(in);
            }

            String accountUrl = props.getProperty(KEY_ACCOUNT_URL);
            if (accountUrl == null) return null;

            // 2. 使用密钥库验证密钥对
            if (!validateKeyPair(accountKey)) {
                log.warn("存储的密钥对验证失败");
                return null;
            }

            // 3. 绑定账户
            return bindAccount(session, accountKey, new URL(accountUrl));
        } catch (Exception e) {
            log.warn("加载已有账户失败", e);
            return null;
        }
    }

    // 新增方法：保存账户信息到密钥库和属性文件
    private static void saveAccountInfo(URL accountUrl, KeyPair accountKey) throws Exception {
        // 保存账户URL到属性文件
        Properties props = new Properties();
        props.setProperty(KEY_ACCOUNT_URL, accountUrl.toString());
        try (OutputStream out = Files.newOutputStream(Path.of(STORE_FILE))) {
            props.store(out, "ACME Account Information");
        }

        // 保存密钥对到PKCS12密钥库
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(
                accountKey.getPrivate(),
                new java.security.cert.Certificate[]{}
        );
        ks.setEntry("acme-account", entry,
                new KeyStore.PasswordProtection(KEYSTORE_PASSWORD.toCharArray()));

        try (OutputStream out = Files.newOutputStream(Path.of(KEYSTORE_FILE))) {
            ks.store(out, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    // 新增方法：验证密钥对是否匹配
    private static boolean validateKeyPair(KeyPair keyPair) {
        try {
            // 从密钥库加载密钥对进行验证
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Path.of(KEYSTORE_FILE))) {
                ks.load(in, KEYSTORE_PASSWORD.toCharArray());
            }
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
                    ks.getEntry("acme-account",
                            new KeyStore.PasswordProtection(KEYSTORE_PASSWORD.toCharArray()));
            return entry.getPrivateKey().equals(keyPair.getPrivate());
        } catch (Exception e) {
            return false;
        }
    }

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
