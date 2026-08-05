package dev.mikko.scccheck;

import dev.mikko.scccheck.RuleTable.Avail;
import dev.mikko.scccheck.RuleTable.Rule;

/**
 * 单个版本号 -> 判定结果。
 *
 * 🔴 本类是整个工具的全部价值,也是最容易「错得没声音」的地方。
 * 第一注 v0.1.0 的教训:判定规则错了不是「误报」,是**让用户做错事** ——
 * 当时把用户推向了成本高得多的大版本迁移。
 */
public final class Judge {

    public enum Level {
        /** 受影响,且公开仓库里**没有**能升的安全版 —— 本工具存在的理由 */
        NO_OSS_FIX,
        /** 受影响,但升个小版本就好 */
        AFFECTED,
        /** 不受影响 */
        SAFE,
        /** 🔴 判不了 —— 绝不许静默当成 SAFE */
        UNKNOWN
    }

    public record Verdict(Level level, String version, String line, String advice) { }

    public static Verdict judge(String version) {
        String line = Versions.line(version);
        if (line == null) {
            return new Verdict(Level.UNKNOWN, version, null,
                    "版本号无法解析,请人工确认。**不要当成安全**。");
        }

        for (Rule r : RuleTable.RULES) {
            boolean aboveLo = (r.lo() == null) || Versions.compare(version, r.lo()) >= 0;
            boolean withinHi = Versions.compare(version, r.hi()) <= 0;

            if (aboveLo && withinHi) {                       // 落在受影响区间内
                if (r.avail() == Avail.ENTERPRISE_ONLY) {
                    return new Verdict(Level.NO_OSS_FIX, version, r.line(), String.format(
                            "受影响。官方修复版 %s 属 Enterprise Support,**Maven Central 上不存在**"
                            + "(该线公开最高版仅 %s)。唯一出路:跨版本线升到 4.3.3+ 或 5.0.3+,"
                            + "或购买商业支持。",
                            r.patched() == null ? "(advisory 未给出)" : r.patched(), r.ossTop()));
                }
                return new Verdict(Level.AFFECTED, version, r.line(),
                        "受影响。升级到 " + r.patched() + "(同版本线,公开仓库可得)。");
            }

            // 同一条线、且高于受影响上界 -> 这条线上已修好
            if (r.line().equals(line) && !withinHi) {
                return new Verdict(Level.SAFE, version, r.line(), "不受本 CVE 影响。");
            }
        }

        // 🔴 4.0.x 落在这里:advisory 的任何区间都没覆盖它(4.0.0 > 3.1.13)。
        // 绝不许断言它受影响 —— 第二注 pac4j 正是这么错的(靠推测填表)。
        return new Verdict(Level.UNKNOWN, version, line,
                "该版本线**不在官方 advisory 的覆盖范围内**,本工具不做受影响判定。"
                + "注意它同时也已无 OSS 维护,建议升级到 4.3.3+ 或 5.0.3+ 后再评估。");
    }

    private Judge() { }
}
