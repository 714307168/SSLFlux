package cn.sslflux.acmeClient.model;

import lombok.Data;

import java.util.Date;

/**
 * @author liuyg
 * @version 1.0
 * @description: 域名证书过期时间
 * @create 2025/3/21 12:09
 * @date 2025/3/21 12:09
 */
@Data
public class CertificateValidityPeriod {

    private  Date notBefore;
    private  Date notAfter;
    private  String hostname;
}
