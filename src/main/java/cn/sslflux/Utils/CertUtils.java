package cn.sslflux.Utils;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

/**
 * @author liuyg
 * @version 1.0
 * @description: 证书处理工具类
 * @date 2025/3/21 20:40
 */
@Slf4j
public class CertUtils {

    /**
     * 验证证书与私钥匹配性（RSA 专用）
     */
    public static boolean validateKeyPair(String certContent, String privateKeyContent) {
        try {
            // 解析证书公钥
            X509Certificate cert = parseCertificate(certContent);
            PublicKey publicKey = cert.getPublicKey();

            // 解析私钥
            PrivateKey privateKey = parsePrivateKey(privateKeyContent);

            // 仅支持 RSA 验证
            if (!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)) {
                log.error("仅支持 RSA 密钥验证");
                return false;
            }

            // 比较模数 (Modulus)
            RSAPublicKey rsaPub = (RSAPublicKey) publicKey;
            RSAPrivateKey rsaPri = (RSAPrivateKey) privateKey;

            return rsaPub.getModulus().equals(rsaPri.getModulus());

        } catch (Exception e) {
            log.error("密钥对验证失败: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 解析 PEM 格式证书
     */
    public static X509Certificate parseCertificate(String certStr)
            throws CertificateException, IOException {

        // 标准化 PEM 格式
        String normalized = normalizeCert(certStr);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(normalized.getBytes())
        );
    }

    /**
     * 解析 PEM 格式私钥（支持 PKCS#1 和 PKCS#8）
     */
    public static PrivateKey parsePrivateKey(String keyStr)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        try (PEMParser parser = new PEMParser(new StringReader(keyStr))) {
            Object object = parser.readObject();

            // 处理 PKCS#8
            if (object instanceof PKCS8EncodedKeySpec) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePrivate((PKCS8EncodedKeySpec) object);
            }

            // 处理 PKCS#1
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object);
        }
    }

    /**
     * 标准化证书格式
     */
    public static String normalizeCert(String raw) {
        // 提取 Base64 内容
        String base64 = raw
                .replaceAll("-----(BEGIN|END) CERTIFICATE-----", "")
                .replaceAll("\\s+", "");

        // 重组标准 PEM
        return "-----BEGIN CERTIFICATE-----\n" +
                chunkText(base64, 64) +
                "\n-----END CERTIFICATE-----\n";
    }

    /**
     * 添加换行格式化
     */
    public static String chunkText(String text, int chunkSize) {
        return String.join("\n",
                text.replaceAll("(.{"+chunkSize+"})", "$1\n")
                        .split("\n")
        ).trim();
    }

    /**
     * 生成完整证书链PEM格式
     */
    public static String generateFullChainPem(List<X509Certificate> certChain) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            for (X509Certificate cert : certChain) {
                pw.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
            }
        }
        return sw.toString();
    }

    /**
     * 生成PKCS#8格式私钥PEM
     */
    public static String generatePrivateKeyPem(PrivateKey privateKey) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
        }
        return sw.toString();
    }
}
