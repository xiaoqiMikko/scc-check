package dev.mikko.scccheck;

import dev.mikko.scccheck.Judge.Level;
import dev.mikko.scccheck.Judge.Verdict;
import dev.mikko.scccheck.Scanner.Finding;
import dev.mikko.scccheck.Scanner.Kind;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * scc-check —— Spring Cloud Config CVE-2026-40982 离线排查。
 *
 * 退出码:2 = 有版本线在公开仓库里升不上去;1 = 受影响但可升 / 判不了;0 = 未发现;3 = 路径错。
 */
public final class Main {

    static final String VERSION = "0.1.0";

    /**
     * 全部输出走这里,以便控制字符编码。
     *
     * <p>为什么需要:Windows 上 Java 拿不到控制台的真实代码页,{@code file.encoding}
     * 与 {@code chcp} 常常对不上(Java 以为是 GBK、控制台实际是 65001),中文就是乱码。
     * 默认沿用平台编码,乱码时用 {@code --utf8} / {@code --gbk} 手动指定。
     * —— 这套做法沿用前三注,别重新发明。
     */
    private static PrintStream out = System.out;

    public static void main(String[] args) throws Exception {
        List<String> targets = new ArrayList<>();
        String encoding = null;

        for (String a : args) {
            switch (a) {
                case "-h", "--help" -> { usage(); return; }
                case "-v", "--version" -> { System.out.println("scc-check " + VERSION); return; }
                case "--utf8" -> encoding = "UTF-8";
                case "--gbk" -> encoding = "GBK";
                default -> {
                    if (a.startsWith("-")) {
                        System.err.println("未知选项:" + a);
                        System.exit(3);
                    }
                    targets.add(a);
                }
            }
        }
        out = createOut(encoding);

        if (targets.isEmpty()) { usage(); return; }
        Path root = Path.of(targets.get(0));
        if (!Files.exists(root)) {
            out.println("路径不存在: " + root);
            System.exit(3);
        }

        out.println("scc-check " + VERSION + " —— " + RuleTable.CVE + " (" + RuleTable.GHSA + ")");
        out.println("目标: " + root.toAbsolutePath());
        out.println("受影响构件: " + RuleTable.ARTIFACT);
        out.println("-".repeat(72));

        List<Finding> findings = dedupe(Scanner.scan(root));
        if (findings.isEmpty()) {
            out.println("[OK] 没有发现 " + Scanner.SERVER + "。");
            out.println();
            out.println("提示: 本 CVE 只影响**服务端** " + Scanner.SERVER + "。");
            out.println("      只引了 spring-cloud-starter-config(客户端)的项目不受影响。");
            return;
        }

        int worst = 0;
        for (Finding f : findings) {
            String where = f.source() + (f.inner() == null ? "" : " :: " + f.inner());

            if (f.kind() == Kind.CLIENT) {
                out.printf("[OK]       %s%n           客户端构件,**不受本 CVE 影响**(漏洞在服务端)。%n           来源: %s%n%n",
                        where, f.note());
                continue;
            }
            if (f.version() == null) {
                out.printf("[判不了]   %s%n           %s%n%n", where, f.note());
                worst = Math.max(worst, 1);
                continue;
            }

            Verdict v = Judge.judge(f.version());
            String tag = switch (v.level()) {
                case NO_OSS_FIX -> "[CRITICAL]";
                case AFFECTED   -> "[受影响]  ";
                case SAFE       -> "[OK]      ";
                case UNKNOWN    -> "[判不了]  ";
            };
            out.printf("%s %s%n           版本 %s(%s 线,依据: %s)%n           %s%n%n",
                    tag, where, v.version(), v.line() == null ? "?" : v.line(), f.note(), v.advice());

            if (v.level() == Level.NO_OSS_FIX) worst = 2;
            else if (worst < 1 && (v.level() == Level.AFFECTED || v.level() == Level.UNKNOWN)) worst = 1;
        }

        out.println("-".repeat(72));
        if (worst == 2) {
            out.println("[!] 存在「Maven Central 上没有修复版」的版本线 —— 官方修复版属 Enterprise Support。");
            printTable();
        }
        System.exit(worst);
    }

    /**
     * 同一个物理构件被多条线索命中时只报一次,并保留**最可靠**的那条依据。
     *
     * <p>独立 jar 会同时命中「文件名」和「Maven 元数据」——报两遍会让人以为有两个问题。
     * Maven 元数据优先(jar 被改名也认得出);fat jar 里的内嵌构件各算各的。
     */
    static List<Finding> dedupe(List<Finding> raw) {
        Map<String, Finding> best = new LinkedHashMap<>();
        for (Finding f : raw) {
            boolean embedded = f.inner() != null
                    && (f.inner().startsWith("BOOT-INF/lib/") || f.inner().startsWith("WEB-INF/lib/"));
            String key = f.source() + "|" + f.kind() + "|" + (embedded ? f.inner() : "@self");
            Finding cur = best.get(key);
            if (cur == null || rank(f) > rank(cur)) best.put(key, f);
        }
        return new ArrayList<>(best.values());
    }

    /** 依据可靠性:Maven 元数据 > 文件名 > 其它 */
    private static int rank(Finding f) {
        if (f.note().startsWith("Maven 元数据")) return 3;
        if (f.note().contains("文件名")) return 2;
        return 1;
    }

    private static void printTable() {
        out.println();
        out.printf("   %-5s %-20s %-12s %-9s %s%n",
                "线", "受影响区间", "官方修复版", "OSS最高", "公开仓库能升到安全版吗");
        for (RuleTable.Rule r : RuleTable.RULES) {
            out.printf("   %-5s %-20s %-12s %-9s %s%n",
                    r.line(),
                    r.lo() == null ? "<= " + r.hi() : r.lo() + " ~ " + r.hi(),
                    r.patched() == null ? "(未给出)" : r.patched(),
                    r.ossTop(),
                    r.avail() == RuleTable.Avail.OSS ? "能" : "不能 —— 仅商业支持");
        }
        out.println();
        out.println("   注:「官方修复版」为空的三条线,是 GitHub advisory 的结构化数据里就没有。");
        out.println("       Dependabot / OSV 消费的正是这份数据,所以它们给不出升级目标。");
    }

    private static PrintStream createOut(String encoding) {
        // 🔴 本机实测(JDK 17 + Windows Terminal):
        //      控制台 chcp = 65001(UTF-8),而 Java 报 file.encoding = native.encoding = GBK,
        //      且 JDK 17 **没有** sun.stdout.encoding 这个属性。
        //    → Java 拿不到控制台真实代码页,任何自动探测都会猜错,这台机器上就得 --utf8。
        //    下面的顺序只是在更新的 JDK 上尽量准一点,**不要指望它能自动猜对**。
        String enc = encoding;
        if (enc == null) enc = System.getProperty("sun.stdout.encoding");
        if (enc == null) enc = System.getProperty("native.encoding");
        if (enc == null) enc = System.getProperty("file.encoding");
        try {
            return new PrintStream(new FileOutputStream(FileDescriptor.out), true, enc);
        } catch (Exception e) {
            return System.out;   // 拿不到就退回默认,不因为编码问题让工具跑不起来
        }
    }

    private static void usage() {
        out.println("""
            scc-check —— Spring Cloud Config CVE-2026-40982 离线排查工具

              用法:  java -jar scc-check.jar <目录或 jar/war 路径> [--utf8|--gbk]

              查什么:
                你的 spring-cloud-config-server 是否受 CVE-2026-40982(目录穿越)影响,
                以及 —— **你这条版本线在 Maven Central 上到底有没有能升的安全版**。

              为什么需要它:
                3.1.x / 4.1.x / 4.2.x 三条线的官方修复版属 Enterprise Support,
                Maven Central 上根本不存在(该线公开最高版分别只到 3.1.10 / 4.1.7 / 4.2.4)。
                用 OSS 的人怎么升都升不到安全版,而 advisory 结构化数据里这三条线的
                first_patched_version 是空的,所以自动化工具不会告诉你这件事。

              选项:
                --utf8 / --gbk   中文乱码时手动指定控制台编码
                -v, --version    版本   -h, --help  本帮助

              退出码: 2=有线升不上去  1=受影响可升/判不了  0=未发现  3=用法或路径错
            """);
    }

    private Main() { }
}
