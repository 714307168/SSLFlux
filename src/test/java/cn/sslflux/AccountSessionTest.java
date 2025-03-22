package cn.sslflux;

import cn.sslflux.acmeClient.core.AccountSession;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Account;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author liuyg
 * @version 1.0
 * @description: 初始化账户测试
 * @date 2025/3/21 19:12
 */
@SpringBootTest(classes = SslFluxApplication.class)
public class AccountSessionTest {
    @Autowired
    private AccountSession accountSession;

    private static final String TEST_KEYSTORE = "D:/sslcret/keystore.p12";
    private static final String STORE_FILE = "acme_account.properties";



    @Test
    void testCreateNewAccount() throws Exception {
        // 当第一次运行时
        Account account = accountSession.initializeAccount();

        // 验证账户创建结果
        assertNotNull(account, "账户对象不应为空");
        assertTrue(Files.exists(Path.of(TEST_KEYSTORE)), "应生成密钥库文件");
        assertTrue(Files.exists(Path.of(STORE_FILE)), "应生成账户属性文件");

    }
}
