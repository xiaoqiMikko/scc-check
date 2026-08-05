#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""从两个一手数据源生成判定表 —— 不手抄。

    源 A  GitHub advisory GHSA-6g23-24mc-hx6x  -> 受影响版本区间 + 官方修复版
    源 B  repo1.maven.org maven-metadata.xml   -> 公开仓库**实际存在**的版本

生成:  ../src/main/java/dev/mikko/scccheck/RuleTable.java

跑:    python tools/gen_rules.py

🔴 为什么必须生成而不是手抄(第四注 bc-check 的教训,`docs/10-教训.md`):
   手抄的表在源数据变化时不会报错,只会安静地过期;而且抄错一格,
   37 个测试可以照样全绿 —— 判定表是这类工具的**全部价值**,错了就是
   「判定规则错了不是误报,是让用户做错事」。

🔴 断言(解析失败必须炸,不许生成空壳表):
   ① 至少 5 条受影响区间       ② 至少 3 条线的 first_patched 为 null
   ③ OSS 最高版必须解析出 5 条线 ④ 至少 3 条线「官方修复版 > OSS 最高版」
   缺任何一条 -> 直接 SystemExit,不写文件。少了它,解析一失败就会生成
   一张空表,而单元测试对着空表照样全绿(第四注原话)。
"""
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

GHSA = "GHSA-6g23-24mc-hx6x"
CVE = "CVE-2026-40982"
GA = "org.springframework.cloud:spring-cloud-config-server"
METADATA = ("https://repo1.maven.org/maven2/org/springframework/cloud/"
            "spring-cloud-config-server/maven-metadata.xml")
OUT = Path(__file__).resolve().parent.parent / "src/main/java/dev/mikko/scccheck/RuleTable.java"


def ver_key(v: str):
    """语义化版本比较键。1.0.0.RELEASE / 5.0.0-M1 都要能排。

    预发布(-M1/-RC1)必须排在正式版之前,否则 5.0.0-M1 会被当成 >= 5.0.0
    而误判为受影响 —— 而它其实早于 5.0.0。
    """
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", v)
    if not m:
        return (0, 0, 0, 0, "")
    major, minor, patch, rest = int(m[1]), int(m[2]), int(m[3]), m[4]
    pre = 0 if (rest == "" or rest.upper().startswith(".RELEASE")) else -1
    return (major, minor, patch, pre, rest)


def fetch_advisory() -> list[dict]:
    out = subprocess.run(["gh", "api", f"advisories/{GHSA}"],
                         capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        raise SystemExit(f"🔴 拉 advisory 失败,不生成表:{out.stderr[:400]}")
    rows = []
    for v in json.loads(out.stdout).get("vulnerabilities", []):
        pkg = (v.get("package") or {}).get("name")
        if pkg != GA:
            continue
        rows.append({"range": v.get("vulnerable_version_range", ""),
                     "patched": v.get("first_patched_version")})
    return rows


def parse_range(r: str) -> tuple[str | None, str]:
    """'>= 4.1.0, <= 4.1.9' -> ('4.1.0','4.1.9');  '<= 3.1.13' -> (None,'3.1.13')"""
    lo = re.search(r">=\s*([\w.\-]+)", r)
    hi = re.search(r"<=\s*([\w.\-]+)", r)
    if not hi:
        raise SystemExit(f"🔴 区间没有上界,解析失败:{r!r}")
    return (lo[1] if lo else None), hi[1]


def fetch_versions() -> list[str]:
    with urllib.request.urlopen(METADATA, timeout=30) as resp:
        xml = resp.read().decode("utf-8", "replace")
    vs = re.findall(r"<version>([^<]+)</version>", xml)
    if len(vs) < 50:
        raise SystemExit(f"🔴 metadata 只解析出 {len(vs)} 个版本,不合理,不生成表")
    return vs


def line_of(v: str) -> str:
    """版本 -> 版本线。4.2.4 -> '4.2';3.1.10 -> '3.1'"""
    m = re.match(r"^(\d+)\.(\d+)\.", v)
    return f"{m[1]}.{m[2]}" if m else "?"


def main() -> int:
    vulns = fetch_advisory()
    versions = fetch_versions()

    # OSS 实际可得:每条线的最高**正式**版(排除 -M/-RC 预发布)
    oss_top: dict[str, str] = {}
    for v in versions:
        if re.search(r"-(M\d+|RC\d+)$", v):
            continue
        ln = line_of(v)
        if ln not in oss_top or ver_key(v) > ver_key(oss_top[ln]):
            oss_top[ln] = v

    rules = []
    for row in vulns:
        lo, hi = parse_range(row["range"])
        ln = line_of(hi)
        patched = row["patched"]
        top = oss_top.get(ln)
        # 🔴 这一列是本工具的全部价值:公开仓库里到底有没有能升的安全版
        if patched and top and ver_key(top) >= ver_key(patched):
            avail, target = "OSS", patched
        else:
            avail, target = "ENTERPRISE_ONLY", patched
        rules.append({"line": ln, "lo": lo, "hi": hi, "patched": patched,
                      "ossTop": top, "avail": avail, "target": target})

    # ---- 断言:解析失败必须炸,不许生成空壳表 ----
    if len(rules) < 5:
        raise SystemExit(f"🔴 只解析出 {len(rules)} 条区间(应 ≥5),不生成表")
    n_null = sum(1 for r in rules if r["patched"] is None)
    if n_null < 3:
        raise SystemExit(f"🔴 first_patched 为 null 的只有 {n_null} 条(应 ≥3)—— "
                         "核心主张的技术证据没了,不生成表")
    if len(oss_top) < 5:
        raise SystemExit(f"🔴 只解析出 {len(oss_top)} 条版本线(应 ≥5),不生成表")
    n_ent = sum(1 for r in rules if r["avail"] == "ENTERPRISE_ONLY")
    if n_ent < 3:
        raise SystemExit(f"🔴 只有 {n_ent} 条线判为 ENTERPRISE_ONLY(应 ≥3)—— "
                         "与已核实的 404 证据不符,不生成表")

    rules.sort(key=lambda r: ver_key(r["hi"]))
    body = "\n".join(
        '        new Rule("{line}", {lo}, "{hi}", {patched}, "{top}", Avail.{avail}),'.format(
            line=r["line"],
            lo=f'"{r["lo"]}"' if r["lo"] else "null",
            hi=r["hi"],
            patched=f'"{r["patched"]}"' if r["patched"] else "null",
            top=r["ossTop"] or "",
            avail=r["avail"],
        ) for r in rules)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(f"""package dev.mikko.scccheck;

import java.util.List;

/**
 * 判定表 —— 由 tools/gen_rules.py 从一手数据生成,**不要手工编辑**。
 *
 * 源 A  GitHub advisory {GHSA}(受影响区间 + 官方修复版)
 * 源 B  repo1.maven.org maven-metadata.xml(公开仓库实际存在的版本)
 *
 * ossTop 是该版本线在 Maven Central 上**实际能拿到**的最高正式版。
 * 当官方修复版高于 ossTop 时,该线判为 ENTERPRISE_ONLY ——
 * 意思是:用 OSS 的人在公开仓库里**升不到安全版**。
 */
public final class RuleTable {{

    public static final String CVE = "{CVE}";
    public static final String GHSA = "{GHSA}";
    public static final String ARTIFACT = "{GA}";

    public enum Avail {{ OSS, ENTERPRISE_ONLY }}

    /**
     * @param lo      受影响区间下界,null 表示无下界(该线及更早全部受影响)
     * @param hi      受影响区间上界(含)
     * @param patched 官方修复版;null = advisory 的结构化数据里**根本没给**
     *                (Dependabot / OSV 消费的就是它,所以它们给不出升级目标)
     * @param ossTop  Maven Central 上该线实际最高正式版
     */
    public record Rule(String line, String lo, String hi, String patched,
                       String ossTop, Avail avail) {{ }}

    public static final List<Rule> RULES = List.of(
{body[:-1]}
    );

    private RuleTable() {{ }}
}}
""", encoding="utf-8")

    print(f"✅ 生成 {OUT.name}:{len(rules)} 条区间,{len(oss_top)} 条版本线")
    print(f"   其中 first_patched=null:{n_null} 条;判为 ENTERPRISE_ONLY:{n_ent} 条")
    for r in rules:
        print(f"   {r['line']:<5} 受影响 {(r['lo'] or '(无下界)'):>8} ~ {r['hi']:<8} "
              f"官方修复={str(r['patched']):<7} OSS最高={r['ossTop']:<8} -> {r['avail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
