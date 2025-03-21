package cn.sslflux.cloudAdapters;

import cn.sslflux.acmeClient.core.CertificateExpirationChecker;
import cn.sslflux.acmeClient.model.CertificateValidityPeriod;
import com.aliyun.auth.credentials.Credential;
import com.aliyun.auth.credentials.provider.StaticCredentialProvider;
import com.aliyun.sdk.service.cdn20180510.AsyncClient;
import com.aliyun.sdk.service.cdn20180510.models.DescribeUserDomainsRequest;
import com.aliyun.sdk.service.cdn20180510.models.DescribeUserDomainsResponse;
import darabonba.core.client.ClientOverrideConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * @author liuyg
 * @version 1.0
 * @description: 阿里云cdn
 * @date 2025/3/21 10:25
 */
@Component
@Slf4j
public class AliyunCDN {

    @Value("${sslflux.cloud.aliyun.access-key}")
    private String ACCESS_KEY;
    @Value("${sslflux.cloud.aliyun.secret-key}")
    private String SECRET_KEY;

    public List<CertificateValidityPeriod> getDomainList() {

        StaticCredentialProvider provider = StaticCredentialProvider.create(Credential.builder()
                .accessKeyId(ACCESS_KEY)
                .accessKeySecret(SECRET_KEY)
                .build());
        AsyncClient client = AsyncClient.builder()
                .region("cn-beijing") // Region ID
                .credentialsProvider(provider)
                .overrideConfiguration(ClientOverrideConfiguration.create().setEndpointOverride("cdn.aliyuncs.com"))
                .build();
        DescribeUserDomainsRequest describeUserDomainsRequest = DescribeUserDomainsRequest.builder().pageSize(500).build();
        CompletableFuture<DescribeUserDomainsResponse> response = client.describeUserDomains(describeUserDomainsRequest);
        DescribeUserDomainsResponse resp = null;
        try {
            resp = response.get();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 创建一个List来存储域名
        List<CertificateValidityPeriod> domainList = new ArrayList<>();
        resp.getBody().getDomains().getPageData().forEach(domain -> {
            domainList.add(CertificateExpirationChecker.checkDomainCertificateExpiration(domain.getDomainName()));
        });
        // 打印List中的证书有效期
        domainList.forEach(period -> {
            System.out.println("Domain: " + period.getHostname() + "   =  " + period.getNotBefore() + " - " + period.getNotAfter());
        });
        // 打印List中的域名
        client.close();
        return domainList;
    }

}
