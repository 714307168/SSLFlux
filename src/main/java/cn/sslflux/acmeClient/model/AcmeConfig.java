package cn.sslflux.acmeClient.model;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author liuyg
 * @version 1.0
 * @description: ACME客户端配置
 * @date 2025/3/20 12:15
 */
@Data
@Component
@ConfigurationProperties(prefix = "acme")
public class AcmeConfig {
    private String serverUri;
}
