package cn.sslflux.Utils;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @author liuyg
 * @version 1.0
 * @description: 文件路径工具类
 * @date 2025/3/21 19:15
 */
public class PathUtils {

    /**
     * 将资源路径转换为系统路径
     * @param resourcePath 配置中的路径（支持 file://、classpath: 等格式）
     * @return 系统绝对路径
     */
    public static Path parseResourcePath(String resourcePath) throws Exception {
        try {
            // 处理URI特殊字符
            String encodedPath = resourcePath
                    .replace(" ", "%20")
                    .replace("[", "%5B")
                    .replace("]", "%5D");

            URI uri = new URI(encodedPath);

            if ("file".equals(uri.getScheme())) {
                return Paths.get(uri);
            }

            return Paths.get(uri.getPath());
        } catch (Exception ex) {
            throw new Exception("路径解析失败: " + resourcePath, ex);
        }
    }
}
