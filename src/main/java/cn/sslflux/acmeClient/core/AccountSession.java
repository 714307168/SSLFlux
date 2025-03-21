package cn.sslflux.acmeClient.core;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;

/**
 * ACME账户管理核心类，负责：
 * 1. 初始化ACME账户
 * 2. 密钥对管理
 * 3. 账户信息持久化
 *
 * @author liuyg
 * @version 2.0
 */
@Slf4j
@Component
public class AccountSession {
    // 账户信息存储文件
    private static final String STORE_FILE = "acme_account.properties";
    // 属性文件中存储账户URL的键
    private static final String KEY_ACCOUNT_URL = "account.url";
    // 密钥库条目别名
    private static final String KEYSTORE_ALIAS = "acme-account";

    private static final int KEY_SIZE = 2048;
    private static final String KEY_ALGORITHM = "RSA";

    // ACME服务器地址（从配置注入）
    @Value("${acme.serverUri}")
    private String serverUri;

    // PKCS12密钥库文件路径（从配置注入）
    @Value("${acme.keystore.file}")
    private String keystoreFile;

    // 密钥库密码（使用char[]避免字符串驻留）
    @Value("${acme.keystore.password}")
    private char[] keystorePassword;

    // 账户联系邮箱（从配置注入）
    @Value("${acme.contact.email}")
    private String contactEmail;

    @Autowired
    private ResourceLoader resourceLoader;

    /**
     * 初始化ACME账户入口方法
     * @return 初始化成功的Account对象
     * @throws AcmeException 账户初始化失败时抛出
     */
    public Account initializeAccount() throws Exception {
        try {
            Session session = new Session(serverUri);
            KeyPair accountKey = loadOrCreateKeyPair();
            return loadExistingAccount(session, accountKey) != null ?
                    loadExistingAccount(session, accountKey) :
                    createNewAccount(session, accountKey);
        } catch (Exception e) {
            throw new AcmeException("账户初始化失败", e);
        }
    }

    /**
     * @description: 密钥对加载/创建方法
     * @author liuyg
     * @date 2025/3/21 19:23
     * @version 1.0
     */
    private KeyPair loadOrCreateKeyPair() throws Exception {
        try {
            return loadKeyPair();
        } catch (FileNotFoundException ex) {
            log.info("首次运行，生成新密钥对...");
            KeyPair newKeyPair = generateKeyPair();
            saveKeyPair(newKeyPair);
            return newKeyPair;
        }
    }

    /**
     * @description: 生成新的RSA密钥对
     * @author liuyg
     * @date 2025/3/21 19:23
     * @version 1.0
     */
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyGen.initialize(KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    /**
     * 从PKCS12密钥库加载密钥对
     * @return 加载的密钥对
     * @throws GeneralSecurityException 密钥库操作安全异常
     * @throws IOException 文件读写异常
     */
    private KeyPair loadKeyPair() throws GeneralSecurityException, IOException {
        Resource resource = resourceLoader.getResource(keystoreFile);

        if (!resource.exists()) {
            throw new FileNotFoundException("密钥库不存在");
        }

        try (InputStream is = resource.getInputStream()) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(is, keystorePassword);

            String alias = ks.aliases().nextElement();
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, keystorePassword);
            PublicKey publicKey = ks.getCertificate(alias).getPublicKey();

            return new KeyPair(publicKey, privateKey);
        }
    }

    /**
     * 尝试加载已有账户
     * @param session ACME会话对象
     * @param keyPair 账户密钥对
     * @return 存在的账户对象，不存在返回null
     */
    private Account loadExistingAccount(Session session, KeyPair keyPair) {
        try {
            URL accountUrl = loadAccountUrl();
            // 需要同时满足：账户URL存在且密钥对验证通过
            if (accountUrl != null && validateKeyPair(keyPair)) {
                return new Login(accountUrl, keyPair, session).getAccount();
            }
            return null;
        } catch (Exception e) {
            log.warn("Loading existing account failed", e);
            return null;
        }
    }

    /**
     * 创建新ACME账户
     * @param session ACME会话对象
     * @param keyPair 账户密钥对
     * @return 新建的账户对象
     * @throws AcmeException 账户创建失败时抛出
     */
    private Account createNewAccount(Session session, KeyPair keyPair) throws Exception {
        // 使用ACME4J的建造者模式创建账户
        Account account = new AccountBuilder()
                .addContact("mailto:" + contactEmail) // 添加联系邮箱
                .useKeyPair(keyPair)                // 绑定密钥对
                .agreeToTermsOfService()             // 自动同意服务条款
                .create(session);                    // 创建账户

        // 持久化账户信息
        saveAccountInfo(account.getLocation(), keyPair);
        return account;
    }

    /**
     * 从属性文件加载账户URL
     * @return 账户URL对象，不存在返回null
     * @throws IOException 文件读取异常
     * @throws MalformedURLException URL格式异常
     */
    private URL loadAccountUrl() throws IOException {
        if (!Files.exists(Path.of(STORE_FILE))) return null;

        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(Path.of(STORE_FILE))) {
            props.load(in);
            String urlStr = props.getProperty(KEY_ACCOUNT_URL);
            return urlStr != null ? new URL(urlStr) : null;
        }
    }

    /**
     * 保存账户信息到文件和密钥库
     * @param accountUrl 账户注册URL
     * @param keyPair 账户密钥对
     * @throws Exception 信息保存失败时抛出
     */
    private void saveAccountInfo(URL accountUrl, KeyPair keyPair) throws Exception {
        saveAccountUrl(accountUrl);  // 保存URL到属性文件
        saveKeyPair(keyPair);        // 保存密钥对到PKCS12文件
    }

    /**
     * 保存账户URL到属性文件
     * @param accountUrl 需要保存的账户URL
     * @throws IOException 文件写入异常
     */
    private void saveAccountUrl(URL accountUrl) throws IOException {
        Properties props = new Properties();
        try {
            String normalizedUrl = accountUrl.toURI()         // 转换为URI对象
                    .toASCIIString();
            props.setProperty(KEY_ACCOUNT_URL, normalizedUrl);
            try (OutputStream out = Files.newOutputStream(Path.of(STORE_FILE))) {
                props.store(out, "ACME Account Information");
            }
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 保存密钥对到PKCS12文件
     * @param keyPair 需要保存的密钥对
     * @throws Exception 密钥库操作异常
     */
    private void saveKeyPair(KeyPair keyPair) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        ks.setKeyEntry(
                KEYSTORE_ALIAS,
                keyPair.getPrivate(),
                keystorePassword,
                new Certificate[]{generatePlaceholderCert(keyPair)}
        );

        Resource resource = resourceLoader.getResource(keystoreFile);
        Path path;
        // 处理Windows路径的特殊字符
        if (keystoreFile.startsWith("file:")) {
            String decodedPath = URLDecoder.decode(
                    keystoreFile.substring(5),
                    StandardCharsets.UTF_8
            );
            path = Paths.get(decodedPath);
        } else {
            path = Paths.get(resource.getURI());
        }

        // 自动创建父目录
        if (!Files.exists(path.getParent())) {
            Files.createDirectories(path.getParent());
            log.info("创建密钥库目录: {}", path.getParent());
        }

        try (OutputStream os = Files.newOutputStream(path)) {
            ks.store(os, keystorePassword);
            log.info("新密钥对已保存至: {}", path);
        }
    }



    /**
     * 生成自签名证书（用于密钥库占位）
     * @param keyPair 使用的密钥对
     * @return 生成的X509证书
     * @throws Exception 证书生成失败时抛出
     */
    private X509Certificate generatePlaceholderCert(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=SSLFlux");
        // 使用SHA256withRSA签名算法
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());

        // 证书有效期：当前时间 ~ 1年后
        return new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(
                        subject,
                        BigInteger.valueOf(System.currentTimeMillis()), // 唯一序列号
                        new Date(),
                        new Date(System.currentTimeMillis() + 365L * 86400000), // 有效期1年
                        subject,
                        keyPair.getPublic()
                ).build(signer)
        );
    }

    /**
     * 验证密钥对是否匹配存储的密钥
     * @param keyPair 待验证的密钥对
     * @return 验证结果
     */
    private boolean validateKeyPair(KeyPair keyPair) {
        try {
            Resource resource = resourceLoader.getResource(keystoreFile);
            if (!resource.exists()) {
                throw new FileNotFoundException("密钥库不存在");
            }
            try (InputStream is = resource.getInputStream()) {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(is, keystorePassword);
                // 获取密钥库条目
                KeyStore.Entry entry = ks.getEntry(KEYSTORE_ALIAS,
                        new KeyStore.PasswordProtection(keystorePassword));
                // 比较私钥字节编码
                return Arrays.equals(
                        ((PrivateKey) ((KeyStore.PrivateKeyEntry) entry).getPrivateKey()).getEncoded(),
                        keyPair.getPrivate().getEncoded()
                );
            }

        } catch (Exception e) {
            log.error("Key validation failed", e);
            return false;
        }
    }
}
