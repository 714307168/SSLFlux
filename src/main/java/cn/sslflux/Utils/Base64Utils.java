package cn.sslflux.Utils;

import java.util.Base64;

/**
 * @author liuyg
 * @version 1.0
 * @description: base64工具类
 * @date 2025/3/21 13:54
 */
public class Base64Utils {

    /**
     * 将字节数组编码为Base64字符串
     *
     * @param bytes 字节数组
     * @return Base64编码的字符串
     */
    public static String encodeToString(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * 将Base64字符串解码为字节数组
     *
     * @param base64String Base64编码的字符串
     * @return 字节数组
     */
    public static byte[] decodeFromString(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }
}
