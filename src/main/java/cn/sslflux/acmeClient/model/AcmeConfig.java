package cn.sslflux.acmeClient.model;

import lombok.Data;

import java.net.URI;
import java.net.http.HttpClient;

/**
 * @author liuyg
 * @version 1.0
 * @description: ACME客户端配置
 * @date 2025/3/20 12:15
 */
@Data
public class AcmeConfig {
    private URI serverUri;
    private HttpClient httpClient; // 自定义HTTP客户端


}
