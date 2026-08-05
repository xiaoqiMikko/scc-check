package dev.mikko.scccheck;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 从构件与 pom 中找出 spring-cloud-config-server 的版本。
 *
 * 🔴 三个已经踩过的坑,这里逐个防住:
 *  ① 第二注 pac4j:pom 里有坐标 ≠ 受影响 —— **必须看 scope**,test/provided 不传递给使用者。
 *  ② 第四注 bc-check:官方 jar 可能**没有 Maven 元数据**,且 MANIFEST 可能上兆撑破读取。
 *     -> 元数据、文件名两条路都走,且读取限长。
 *  ③ 本注特有:Spring Cloud 用 release train 统一管版本,**pom 里常常没有 `<version>`**。
 *     -> 这种情况必须明确报「版本由 BOM 决定,读 pom 判不了」,而不是当它不存在。
 */
public final class Scanner {

    /** 服务端构件 —— 只有它受本 CVE 影响 */
    static final String SERVER = "spring-cloud-config-server";
    /** 客户端构件 —— 引了这些的人**不受影响**,但看到 CRITICAL 会白紧张 */
    static final List<String> CLIENTS = List.of("spring-cloud-starter-config",
                                                "spring-cloud-config-client");

    /** MANIFEST / pom.properties 读取上限,防签名清单撑爆内存(第四注实证:上兆) */
    private static final int MAX_META = 512 * 1024;

    public enum Kind { SERVER, CLIENT }

    /**
     * @param version null 表示「找到了坐标但版本未知」(BOM 管版本的典型情况)
     * @param note    补充说明,例如 scope 或 BOM 提示
     */
    public record Finding(Path source, String inner, Kind kind, String version, String note) { }

    private static final Pattern JAR_NAME =
            Pattern.compile("^(" + SERVER + ")-(\\d[\\w.\\-]*)\\.jar$");
    private static final Pattern POM_PROPS_VERSION =
            Pattern.compile("^version=(.+)$", Pattern.MULTILINE);

    public static List<Finding> scan(Path root) throws IOException {
        List<Finding> out = new ArrayList<>();
        if (Files.isRegularFile(root)) {
            scanFile(root, out);
            return out;
        }
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : (Iterable<Path>) s.filter(Files::isRegularFile)::iterator) {
                scanFile(p, out);
            }
        }
        return out;
    }

    private static void scanFile(Path p, List<Finding> out) throws IOException {
        String name = p.getFileName().toString();
        if (name.endsWith(".jar") || name.endsWith(".war")) {
            scanArchive(p, out);
        } else if (name.equals("pom.xml")) {
            scanPom(p, out);
        }
    }

    /** 扫构件:自身文件名 + 内嵌 lib + Maven 元数据。构件不会说谎,优先级最高。 */
    private static void scanArchive(Path jar, List<Finding> out) throws IOException {
        matchJarName(jar.getFileName().toString()).ifPresent(v ->
                out.add(new Finding(jar, null, Kind.SERVER, v, "jar 文件名")));

        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(jar))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                String n = e.getName();

                // fat jar / war 内嵌依赖
                if ((n.startsWith("BOOT-INF/lib/") || n.startsWith("WEB-INF/lib/"))
                        && n.endsWith(".jar")) {
                    String base = n.substring(n.lastIndexOf('/') + 1);
                    matchJarName(base).ifPresent(v ->
                            out.add(new Finding(jar, n, Kind.SERVER, v, "内嵌 jar 文件名")));
                    for (String c : CLIENTS) {
                        if (base.startsWith(c + "-")) {
                            out.add(new Finding(jar, n, Kind.CLIENT, null, "内嵌客户端构件"));
                        }
                    }
                }

                // Maven 元数据 —— 比文件名可靠(jar 被改名也认得出)
                if (n.endsWith("/pom.properties")
                        && n.contains("org.springframework.cloud/" + SERVER)) {
                    String txt = readLimited(zis);
                    Matcher m = POM_PROPS_VERSION.matcher(txt);
                    if (m.find()) {
                        out.add(new Finding(jar, n, Kind.SERVER, m.group(1).trim(),
                                "Maven 元数据(pom.properties)"));
                    }
                }
            }
        }
    }

    private static java.util.Optional<String> matchJarName(String base) {
        Matcher m = JAR_NAME.matcher(base);
        return m.matches() ? java.util.Optional.of(m.group(2)) : java.util.Optional.empty();
    }

    private static String readLimited(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n, total = 0;
        while ((n = in.read(buf)) > 0 && total < MAX_META) {
            bos.write(buf, 0, n);
            total += n;
        }
        return bos.toString(StandardCharsets.UTF_8);
    }

    // pom.xml 里 <dependency> 整块,用于同时拿到 artifactId / version / scope
    private static final Pattern DEP_BLOCK =
            Pattern.compile("<dependency>(.*?)</dependency>", Pattern.DOTALL);
    private static final Pattern TAG_ARTIFACT = Pattern.compile("<artifactId>\\s*([^<]+?)\\s*</artifactId>");
    private static final Pattern TAG_VERSION = Pattern.compile("<version>\\s*([^<]+?)\\s*</version>");
    private static final Pattern TAG_SCOPE = Pattern.compile("<scope>\\s*([^<]+?)\\s*</scope>");
    private static final Pattern COMMENT = Pattern.compile("<!--.*?-->", Pattern.DOTALL);

    /**
     * 扫 pom.xml。**先剥注释** —— 第二注就栽在这:
     * `ratpack-pac4j` 那条整块被 XML 注释包着,却被当成真实依赖读进了判定表。
     */
    private static void scanPom(Path pom, List<Finding> out) throws IOException {
        String xml = COMMENT.matcher(Files.readString(pom, StandardCharsets.UTF_8))
                            .replaceAll("");
        Matcher blocks = DEP_BLOCK.matcher(xml);
        while (blocks.find()) {
            String block = blocks.group(1);
            Matcher a = TAG_ARTIFACT.matcher(block);
            if (!a.find()) continue;
            String artifact = a.group(1);

            Matcher sc = TAG_SCOPE.matcher(block);
            String scope = sc.find() ? sc.group(1) : "compile";

            if (CLIENTS.contains(artifact)) {
                out.add(new Finding(pom, null, Kind.CLIENT, null, "pom 依赖(scope=" + scope + ")"));
                continue;
            }
            if (!SERVER.equals(artifact)) continue;

            // 🔴 第二注的坟:test / provided 不传递给使用者,不能当成受影响
            if (scope.equals("test") || scope.equals("provided")) {
                out.add(new Finding(pom, null, Kind.SERVER, null,
                        "pom 依赖但 scope=" + scope + " —— **不传递**,通常不构成暴露面"));
                continue;
            }

            Matcher v = TAG_VERSION.matcher(block);
            if (v.find() && !v.group(1).startsWith("${")) {
                out.add(new Finding(pom, null, Kind.SERVER, v.group(1),
                        "pom 依赖(scope=" + scope + ")"));
            } else {
                // Spring Cloud 的常态:版本来自 release train BOM,pom 里看不到
                out.add(new Finding(pom, null, Kind.SERVER, null,
                        "pom 里**没有写死版本**(由 spring-cloud-dependencies BOM 决定)"
                        + " —— 读 pom 判不出版本,请改扫构建产物 jar"));
            }
        }
    }

    private Scanner() { }
}
