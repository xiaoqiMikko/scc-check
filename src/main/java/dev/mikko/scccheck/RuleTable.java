package dev.mikko.scccheck;

import java.util.List;

/**
 * 判定表 —— 由 tools/gen_rules.py 从一手数据生成,**不要手工编辑**。
 *
 * 源 A  GitHub advisory GHSA-6g23-24mc-hx6x(受影响区间 + 官方修复版)
 * 源 B  repo1.maven.org maven-metadata.xml(公开仓库实际存在的版本)
 *
 * ossTop 是该版本线在 Maven Central 上**实际能拿到**的最高正式版。
 * 当官方修复版高于 ossTop 时,该线判为 ENTERPRISE_ONLY ——
 * 意思是:用 OSS 的人在公开仓库里**升不到安全版**。
 */
public final class RuleTable {

    public static final String CVE = "CVE-2026-40982";
    public static final String GHSA = "GHSA-6g23-24mc-hx6x";
    public static final String ARTIFACT = "org.springframework.cloud:spring-cloud-config-server";

    public enum Avail { OSS, ENTERPRISE_ONLY }

    /**
     * @param lo      受影响区间下界,null 表示无下界(该线及更早全部受影响)
     * @param hi      受影响区间上界(含)
     * @param patched 官方修复版;null = advisory 的结构化数据里**根本没给**
     *                (Dependabot / OSV 消费的就是它,所以它们给不出升级目标)
     * @param ossTop  Maven Central 上该线实际最高正式版
     */
    public record Rule(String line, String lo, String hi, String patched,
                       String ossTop, Avail avail) { }

    public static final List<Rule> RULES = List.of(
        new Rule("3.1", null, "3.1.13", null, "3.1.10", Avail.ENTERPRISE_ONLY),
        new Rule("4.1", "4.1.0", "4.1.9", null, "4.1.7", Avail.ENTERPRISE_ONLY),
        new Rule("4.2", "4.2.0", "4.2.6", null, "4.2.4", Avail.ENTERPRISE_ONLY),
        new Rule("4.3", "4.3.0", "4.3.2", "4.3.3", "4.3.4", Avail.OSS),
        new Rule("5.0", "5.0.0", "5.0.2", "5.0.3", "5.0.4", Avail.OSS)
    );

    private RuleTable() { }
}
