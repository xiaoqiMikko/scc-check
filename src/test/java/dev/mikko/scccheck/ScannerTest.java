package dev.mikko.scccheck;

import dev.mikko.scccheck.Scanner.Finding;
import dev.mikko.scccheck.Scanner.Kind;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScannerTest {

    private static void writePom(Path dir, String deps) throws Exception {
        Files.writeString(dir.resolve("pom.xml"), """
                <project>
                  <dependencies>
                %s
                  </dependencies>
                </project>
                """.formatted(deps), StandardCharsets.UTF_8);
    }

    private static String dep(String artifact, String version, String scope) {
        return "    <dependency><groupId>org.springframework.cloud</groupId>"
                + "<artifactId>" + artifact + "</artifactId>"
                + (version == null ? "" : "<version>" + version + "</version>")
                + (scope == null ? "" : "<scope>" + scope + "</scope>")
                + "</dependency>";
    }

    @Test
    @DisplayName("🔴 test/provided scope 不传递 —— 不能当成受影响(第二注 pac4j 的坟)")
    void scope不传递(@TempDir Path dir) throws Exception {
        writePom(dir, dep(Scanner.SERVER, "4.2.4", "test")
                + "\n" + dep(Scanner.SERVER, "4.2.4", "provided"));
        List<Finding> fs = Scanner.scan(dir);
        assertEquals(2, fs.size());
        fs.forEach(f -> {
            assertNull(f.version(), "test/provided 不该产出可判定版本");
            assertTrue(f.note().contains("不传递"), "必须说清楚为什么不算");
        });
    }

    @Test
    @DisplayName("🔴 被 XML 注释包住的依赖不算数(第二注 ratpack-pac4j 就是这么误报的)")
    void 注释掉的依赖不算(@TempDir Path dir) throws Exception {
        writePom(dir, "<!--\n" + dep(Scanner.SERVER, "4.2.4", null) + "\n-->");
        assertTrue(Scanner.scan(dir).isEmpty(), "注释里的依赖必须被剥掉");
    }

    @Test
    @DisplayName("BOM 管版本时 pom 里没有 version —— 要报「判不了」,不能当没有")
    void BOM管版本(@TempDir Path dir) throws Exception {
        writePom(dir, dep(Scanner.SERVER, null, null));
        List<Finding> fs = Scanner.scan(dir);
        assertEquals(1, fs.size());
        assertNull(fs.get(0).version());
        assertTrue(fs.get(0).note().contains("BOM"));

        // ${...} 占位符同样判不了
        writePom(dir, dep(Scanner.SERVER, "${spring-cloud.version}", null));
        assertNull(Scanner.scan(dir).get(0).version());
    }

    @Test
    @DisplayName("客户端构件必须判为 CLIENT —— 近 10 万项目引了它,别吓人")
    void 客户端不受影响(@TempDir Path dir) throws Exception {
        writePom(dir, dep("spring-cloud-starter-config", "4.2.4", null));
        List<Finding> fs = Scanner.scan(dir);
        assertEquals(1, fs.size());
        assertEquals(Kind.CLIENT, fs.get(0).kind());
    }

    @Test
    @DisplayName("同一构件被文件名和 Maven 元数据同时命中时,只报一次且保留元数据依据")
    void 去重(@TempDir Path dir) throws Exception {
        Path jar = dir.resolve("spring-cloud-config-server-4.2.4.jar");
        List<Finding> raw = List.of(
                new Finding(jar, null, Kind.SERVER, "4.2.4", "jar 文件名"),
                new Finding(jar, "META-INF/maven/org.springframework.cloud/"
                        + Scanner.SERVER + "/pom.properties", Kind.SERVER, "4.2.4",
                        "Maven 元数据(pom.properties)"));
        List<Finding> out = Main.dedupe(raw);
        assertEquals(1, out.size(), "同一个物理构件只该报一条");
        assertTrue(out.get(0).note().startsWith("Maven 元数据"), "该保留更可靠的那条依据");
    }

    @Test
    @DisplayName("fat jar 里的多个内嵌构件各算各的,不能被去重合并掉")
    void 内嵌构件不合并(@TempDir Path dir) throws Exception {
        Path app = dir.resolve("app.jar");
        List<Finding> raw = List.of(
                new Finding(app, "BOOT-INF/lib/spring-cloud-config-server-4.2.4.jar",
                        Kind.SERVER, "4.2.4", "内嵌 jar 文件名"),
                new Finding(app, "BOOT-INF/lib/spring-cloud-config-server-5.0.4.jar",
                        Kind.SERVER, "5.0.4", "内嵌 jar 文件名"));
        assertEquals(2, Main.dedupe(raw).size());
    }
}
