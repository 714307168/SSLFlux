package cn.sslflux.Utils;

/**
 * @author liuyg
 * @version 1.0
 * @description: 域名工具类
 * @date 2025/3/21 14:35
 */
public class DomainUtils {


    /**
     * @description: 提取根域名
     * @author liuyg
     * @date 2025/3/21 14:38
     * @version 1.0
     */
    public static String extractRootDomain(String fqdn) {
        String[] parts = fqdn.split("\\.");
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    /**
     * @description: 提取子域名
     * @author liuyg
     * @date 2025/3/21 14:38
     * @version 1.0
     */
    public static String extractSubDomain(String fqdn) {
        return fqdn.replace("." + extractRootDomain(fqdn), "");
    }

    public static void main(String[] args) {
        String fqdn = "www.example.com";
        System.out.println("Root domain: " + extractRootDomain(fqdn));
        System.out.println("Sub domain: " + extractSubDomain(fqdn));
    }
}
