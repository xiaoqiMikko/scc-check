# scc-check

**Spring Cloud Config `CVE-2026-40982` 离线排查工具** —— 零依赖、单 jar、不联网。

它回答的不是「我受不受影响」,而是那个更难受的问题:

> ## 我这条版本线,在 Maven Central 上到底有没有能升的安全版?

对 **3.1.x / 4.1.x / 4.2.x** 三条线,答案是 **没有**。

---

## 为什么需要它

官方 advisory([spring.io/security/cve-2026-40982](https://spring.io/security/cve-2026-40982))给出的修复版:

| 版本线 | 官方修复版 | 可得性 | Maven Central 上该线最高版 | 你能升上去吗 |
|---|---|---|---|---|
| 3.1.x | 3.1.14 | **Enterprise Support Only** | **3.1.10** | ❌ |
| 4.1.x | 4.1.10 | **Enterprise Support Only** | **4.1.7** | ❌ |
| 4.2.x | 4.2.7 | **Enterprise Support Only** | **4.2.4** | ❌ |
| 4.3.x | 4.3.3 | OSS | 4.3.4 | ✅ |
| 5.0.x | 5.0.3 | OSS | 5.0.4 | ✅ |

那三个修复版本**不在公开仓库里**。任何人都能验证:

```bash
curl -sI https://repo1.maven.org/maven2/org/springframework/cloud/spring-cloud-config-server/4.2.7/
# HTTP/1.1 404 Not Found
```

**而且自动化工具不会告诉你这件事** —— GitHub advisory 的结构化数据里,
这三条线的 `first_patched_version` 就是 `null`:

```jsonc
{"range": "<= 3.1.13",          "first_patched_version": null}
{"range": ">= 4.1.0, <= 4.1.9", "first_patched_version": null}
{"range": ">= 4.2.0, <= 4.2.6", "first_patched_version": null}
{"range": ">= 4.3.0, <= 4.3.2", "first_patched_version": "4.3.3"}
{"range": ">= 5.0.0, <= 5.0.2", "first_patched_version": "5.0.3"}
```

Dependabot / OSV 消费的正是这份数据。**没有升级目标,就给不出升级建议。**

---

## 用法

```bash
java -jar scc-check.jar <目录或 jar/war 路径>

# 中文乱码时(Windows 控制台代码页与 Java 判断常常对不上):
java -jar scc-check.jar target/ --utf8
```

需要 **Java 17+**。运行时零依赖,可直接丢进离线环境。

**退出码**:`2` 有版本线升不上去 · `1` 受影响但可升 / 判不了 · `0` 未发现 · `3` 用法或路径错

### 它查哪些地方

- `.jar` / `.war` 文件名
- Spring Boot fat jar 与 war 的内嵌依赖(`BOOT-INF/lib/`、`WEB-INF/lib/`)
- jar 内 Maven 元数据(`META-INF/maven/.../pom.properties`)—— **jar 被改名也认得出**
- `pom.xml`

---

## 三件它刻意不做的事

**1. 不把客户端算成受影响。**
本 CVE 只影响服务端 `spring-cloud-config-server`。引了 `spring-cloud-starter-config`
(客户端)的项目**不受影响**,工具会明确告诉你,而不是让你白紧张。

**2. 不对 4.0.x 下判定。**
官方 advisory 的任何区间都没有覆盖 4.0.x(`4.0.0 > 3.1.13`,不落在无下界那条里)。
工具只报「不在官方覆盖范围内」,**不报 CRITICAL** —— 靠推测填判定表会让人做错决定。

**3. 读不出版本时明说「判不了」,绝不当成安全。**
Spring Cloud 用 release train 统一管版本,`pom.xml` 里常常**根本没有 `<version>`**。
这种情况工具会告诉你去扫构建产物,而不是假装没找到问题。
同样,`scope` 为 `test` / `provided` 的依赖不传递给使用者,不算暴露面;
被 XML 注释包住的依赖会被剥掉。

---

## 判定表是生成的,不是手抄的

`tools/gen_rules.py` 从两个一手数据源编译出 `RuleTable.java`:

- **GitHub advisory** `GHSA-6g23-24mc-hx6x` → 受影响区间 + 官方修复版
- **`repo1.maven.org` 的 `maven-metadata.xml`** → 公开仓库里**实际存在**的版本

并带四条断言:区间数 ≥5、`first_patched=null` 的 ≥3、版本线 ≥5、判为
`ENTERPRISE_ONLY` 的 ≥3。**任何一条不满足就直接中止,不生成文件** ——
否则解析一失败就会产出一张空表,而单元测试对着空表照样全绿。

```bash
python tools/gen_rules.py     # 重新生成判定表
mvn test                      # 31 个测试
```

---

## 免责

本工具只做**版本比对**,不检测你的 Config Server 是否真的暴露在公网、
是否有 WAF、是否已通过其它方式缓解。判定结果是排查起点,不是安全结论。
以官方 advisory 为准。

## License

MIT

<!-- cta:hire -->

---

## 需要更进一步的排查?

这个工具回答的是「**我中没中**」。下面这些它答不了,可以找我做:

- 依赖被 shade / relocate 过,或者构建产物根本拿不到
- 要判的是「这条 CVE 在**我们的调用链上**到底会不会触发」,而不只是版本命中
- 要按你们自己的构建流程或内网环境做定制、接进现有流水线
- 手上是**另一个**组件的同类问题,还没有现成工具

📮 **sikongjuechen@gmail.com** —— 说清情况,我 24 小时内给你一页书面答复:
能不能做、难在哪、大概多久。**这一步免费,也不用你先承诺什么。**
