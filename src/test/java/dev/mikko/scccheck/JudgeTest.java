package dev.mikko.scccheck;

import dev.mikko.scccheck.Judge.Level;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class JudgeTest {

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
            // ── 三条「公开仓库升不上去」的线 ──────────────────────────
            "3.1.10, NO_OSS_FIX",   // 该线 OSS 实际最高版,仍受影响
            "3.1.13, NO_OSS_FIX",   // 受影响区间上界
            "4.1.7,  NO_OSS_FIX",   // 该线 OSS 实际最高版
            "4.1.9,  NO_OSS_FIX",
            "4.2.4,  NO_OSS_FIX",   // 该线 OSS 实际最高版
            "4.2.6,  NO_OSS_FIX",

            // ── 无下界区间 `<= 3.1.13`:更老的线全部落进来 ────────────
            "3.0.6,  NO_OSS_FIX",
            "2.2.8.RELEASE, NO_OSS_FIX",
            "1.4.7.RELEASE, NO_OSS_FIX",

            // ── 商业版本号(公开仓库没有,但用户可能真在用)──────────
            "3.1.14, SAFE",
            "4.1.10, SAFE",
            "4.2.7,  SAFE",

            // ── 两条能自救的线 ──────────────────────────────────────
            "4.3.0,  AFFECTED",
            "4.3.2,  AFFECTED",
            "4.3.3,  SAFE",
            "4.3.4,  SAFE",
            "5.0.0,  AFFECTED",
            "5.0.2,  AFFECTED",
            "5.0.3,  SAFE",
            "5.0.4,  SAFE",
    })
    void 判定(String version, Level expected) {
        assertEquals(expected, Judge.judge(version).level(),
                "版本 " + version + " 判错了 —— 判定规则错了不是误报,是让用户做错事");
    }

    @Test
    @DisplayName("🔴 4.0.x 不在 advisory 任何区间内 —— 绝不许断言它受影响(第二注 pac4j 的坟)")
    void 未覆盖的版本线不许断言受影响() {
        for (String v : new String[]{"4.0.0", "4.0.3", "4.0.5"}) {
            var verdict = Judge.judge(v);
            assertEquals(Level.UNKNOWN, verdict.level(), v + " 应判为 UNKNOWN");
            assertTrue(verdict.advice().contains("不在官方 advisory 的覆盖范围内"),
                    "必须说清楚是「没覆盖」而不是「安全」");
        }
    }

    @Test
    @DisplayName("预发布版排在同号正式版之前,不能被算进 >= 5.0.0")
    void 预发布不误判() {
        assertTrue(Versions.compare("5.0.0-M1", "5.0.0") < 0);
        assertTrue(Versions.compare("5.0.0-RC1", "5.0.0") < 0);
        assertTrue(Versions.compare("2.2.8.RELEASE", "3.0.0") < 0);
        assertTrue(Versions.compare("4.2.4", "4.2.7") < 0);
    }

    @Test
    @DisplayName("版本号解析不了必须报 UNKNOWN,绝不许静默当成安全")
    void 解析失败不许当成安全() {
        for (String v : new String[]{"", "abc", "4.x", "${spring-cloud.version}"}) {
            assertEquals(Level.UNKNOWN, Judge.judge(v).level(), v + " 应为 UNKNOWN");
        }
        assertThrows(IllegalArgumentException.class, () -> Versions.compare("abc", "1.0.0"));
    }

    @Test
    @DisplayName("判定表不是空壳,且三条线确实判为「公开仓库升不上去」")
    void 判定表完整性() {
        assertEquals(5, RuleTable.RULES.size(), "应有 5 条受影响区间");

        long entOnly = RuleTable.RULES.stream()
                .filter(r -> r.avail() == RuleTable.Avail.ENTERPRISE_ONLY).count();
        assertEquals(3, entOnly, "3.1 / 4.1 / 4.2 三条线应判为 ENTERPRISE_ONLY");

        long noPatch = RuleTable.RULES.stream().filter(r -> r.patched() == null).count();
        assertEquals(3, noPatch,
                "这三条线在 advisory 结构化数据里就没有 first_patched_version —— 核心主张的技术证据");

        // 每条规则都必须有 OSS 最高版,否则「能不能升」这一列就是瞎写的
        RuleTable.RULES.forEach(r ->
                assertNotNull(Versions.parse(r.ossTop()), r.line() + " 线缺 ossTop"));
    }

    @Test
    @DisplayName("ENTERPRISE_ONLY 的判定必须真的成立:官方修复版 > 该线 OSS 最高版")
    void 收费判定必须与版本事实一致() {
        for (RuleTable.Rule r : RuleTable.RULES) {
            if (r.avail() != RuleTable.Avail.OSS) continue;
            assertTrue(Versions.compare(r.ossTop(), r.patched()) >= 0,
                    r.line() + " 判为 OSS,那 ossTop 必须 >= 官方修复版");
        }
    }
}
