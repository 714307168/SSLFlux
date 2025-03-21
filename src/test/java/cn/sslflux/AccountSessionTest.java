package cn.sslflux;

import cn.sslflux.acmeClient.core.AccountSession;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Account;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author liuyg
 * @version 1.0
 * @description: 初始化账户测试
 * @date 2025/3/21 19:12
 */
@SpringBootTest
@ActiveProfiles("test")
public class AccountSessionTest {
    @Autowired
    private AccountSession accountSession;

    @Value("${acme.keystore.file}")
    private String keystorePath;


    @Test
    void testFirstRun() throws Exception {
        Account account = accountSession.initializeAccount();
        assertNotNull(account);

        // 验证文件已创建
        Resource resource = new DefaultResourceLoader().getResource(keystorePath);
        assertTrue(resource.exists());

        // 验证账户信息
        assertNotNull(account.getLocation());
    }
}
