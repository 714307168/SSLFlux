package cn.sslflux.acmeClient.core;

/**
 * @description: DNS挑战处理器
 * @author liuyg
 * @date 2025/3/21 13:13
 * @version 1.0
 */
public interface DnsProvider {

    void addTxtRecord(String name, String value) throws Exception;

    void removeTxtRecord(String name) throws Exception;

    boolean checkPropagation(String name, String value) throws Exception;
}
