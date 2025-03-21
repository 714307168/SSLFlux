package cn.sslflux.cloudAdapters;

import com.aliyun.auth.credentials.Credential;
import com.aliyun.auth.credentials.provider.StaticCredentialProvider;
import com.aliyun.sdk.service.alidns20150109.AsyncClient;
import com.aliyun.sdk.service.alidns20150109.models.AddDomainRecordRequest;
import com.aliyun.sdk.service.alidns20150109.models.AddDomainRecordResponse;
import com.aliyun.sdk.service.alidns20150109.models.DeleteSubDomainRecordsRequest;
import com.aliyun.sdk.service.alidns20150109.models.DeleteSubDomainRecordsResponse;
import darabonba.core.client.ClientOverrideConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

/**
 * @author liuyg
 * @version 1.0
 * @description: 阿里云DNS添加解析记录
 * @date 2025/3/21 12:43
 */

@Slf4j
@Component
public class AliyunDomain {

    @Value("${sslflux.cloud.aliyun.access-key}")
    private String ACCESS_KEY;
    @Value("${sslflux.cloud.aliyun.secret-key}")
    private String SECRET_KEY;

    /**
     * @description: 添加DNS记录
     * @author liuyg
     * @date 2025/3/21 13:24
     * @version 1.0
     */
    public boolean AddDomainRecord(String domainName, String rr, String type, String value) {
        StaticCredentialProvider provider = StaticCredentialProvider.create(Credential.builder()
                .accessKeyId(ACCESS_KEY)
                .accessKeySecret(SECRET_KEY)
                .build());
        AsyncClient client = AsyncClient.builder()
                .region("cn-beijing") // Region ID
                .credentialsProvider(provider)
                .overrideConfiguration(
                        ClientOverrideConfiguration.create()
                                .setEndpointOverride("alidns.cn-beijing.aliyuncs.com")
                )
                .build();
        AddDomainRecordRequest addDomainRecordRequest = AddDomainRecordRequest.builder()
                .domainName(domainName)
                .rr(rr)
                .type(type)
                .value(value)
                .build();
        CompletableFuture<AddDomainRecordResponse> response = client.addDomainRecord(addDomainRecordRequest);
        AddDomainRecordResponse resp = null;
        try {
            resp = response.get();
        } catch (Exception e) {
            log.error("域名添加dns记录失败，报错信息", e);
            return false;
        }
        return resp.getStatusCode() == 200;
    }

    public boolean DeleteDomainRecord(String domainName, String rr) {
        StaticCredentialProvider provider = StaticCredentialProvider.create(Credential.builder()
                .accessKeyId(ACCESS_KEY)
                .accessKeySecret(SECRET_KEY)
                .build());
        AsyncClient client = AsyncClient.builder()
                .region("cn-beijing")
                .credentialsProvider(provider)
                .overrideConfiguration(ClientOverrideConfiguration.create().setEndpointOverride("alidns.cn-beijing.aliyuncs.com"))
                .build();
        DeleteSubDomainRecordsRequest deleteSubDomainRecordsRequest = DeleteSubDomainRecordsRequest.builder()
                .domainName(domainName)
                .rr(rr)
                .build();
        CompletableFuture<DeleteSubDomainRecordsResponse> response = client.deleteSubDomainRecords(deleteSubDomainRecordsRequest);
        DeleteSubDomainRecordsResponse resp = null;
        try {
            resp = response.get();
        } catch (Exception e) {
            log.error("域名删除dns记录失败，报错信息", e);
            return false;
        }
        client.close();
        return resp.getStatusCode() == 200;
    }
}
