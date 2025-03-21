package cn.sslflux.acmeClient.core;


import cn.sslflux.acmeClient.model.CertificateValidityPeriod;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.util.Date;

/**
 * @author liuyg
 * @version 1.0
 * @description: 检测证书是否过期
 * @date 2025/3/21 11:25
 */
public class CertificateExpirationChecker {

    public static CertificateValidityPeriod checkDomainCertificateExpiration(String hostname) {
        CertificateValidityPeriod certificateValidityPeriod = new CertificateValidityPeriod();
        certificateValidityPeriod.setHostname(hostname);
        int port = 443; // HTTPS的默认端口
        try {
            // 创建自定义 TrustManager，跳过证书验证
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
                            // 不执行任何验证
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType)  {
                            // 不执行任何验证
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[]{};
                        }
                    }
            };

            // 安装自定义 TrustManager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory socketFactory = sc.getSocketFactory();

            // 创建SSLSocket以连接到服务器并获取证书
            SSLSocket socket = (SSLSocket) socketFactory.createSocket(hostname, port);
            socket.startHandshake(); // 确保握手完成以获取证书

            // 获取服务器的证书链
            Certificate[] certs = socket.getSession().getPeerCertificates();
            X509Certificate x509 = (X509Certificate) certs[0]; // 获取第一个证书（通常是服务器证书）

            // 获取证书的有效期
            Date notBefore = x509.getNotBefore(); // 开始日期
            Date notAfter = x509.getNotAfter(); // 结束日期（到期时间）
            certificateValidityPeriod.setNotBefore(notBefore);
            certificateValidityPeriod.setNotAfter(notAfter);
        } catch (Exception e) {

        }
        return certificateValidityPeriod;
    }

    public static void main(String[] args) {
        String hostname = "www.yushuwei.top";
        CertificateValidityPeriod certificateValidityPeriod = checkDomainCertificateExpiration(hostname);
        System.out.println("证书有效期：" + certificateValidityPeriod.getNotBefore() + " - " + certificateValidityPeriod.getNotAfter());
    }
}
