package cn.sslflux.cloudAdapters;

import cn.sslflux.Utils.DomainUtils;
import cn.sslflux.acmeClient.core.DnsProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @author liuyg
 * @version 1.0
 * @description: 阿里云DNS挑战处理器
 * @date 2025/3/21 12:37
 */
@Component
public class AliyunDnsProvider implements DnsProvider {

    @Autowired
    private AliyunDomain aliyunDomain;


    @Override
    public void addTxtRecord(String name, String value) {
        aliyunDomain.AddDomainRecord(DomainUtils.extractRootDomain(name), DomainUtils.extractSubDomain(name), "TXT", value);
    }

    @Override
    public void removeTxtRecord(String name) {
        aliyunDomain.DeleteDomainRecord(DomainUtils.extractRootDomain(name), DomainUtils.extractSubDomain(name));
    }

    @Override
    public boolean checkPropagation(String name, String value) {
        // 实现DNS记录传播检查
        return true; // 简化示例
    }


}
