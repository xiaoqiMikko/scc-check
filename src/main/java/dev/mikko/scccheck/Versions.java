package dev.mikko.scccheck;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 版本号解析与比较。
 *
 * Spring Cloud Config 的版本号横跨两种风格:
 *   老:1.4.7.RELEASE / 2.2.8.RELEASE
 *   新:4.2.4 / 5.0.0-M1 / 5.0.0-RC1
 *
 * 🔴 预发布必须排在同号正式版**之前**,否则 5.0.0-M1 会被判进
 * 「>= 5.0.0」而误报;而它其实早于 5.0.0,不在该区间里。
 */
final class Versions {

    private static final Pattern P = Pattern.compile("^(\\d+)\\.(\\d+)\\.(\\d+)(.*)$");

    /** 无法解析的版本返回 null —— 调用方必须把它当「判不了」,不许当 0 处理。 */
    static int[] parse(String v) {
        if (v == null) return null;
        Matcher m = P.matcher(v.trim());
        if (!m.matches()) return null;
        String rest = m.group(4);
        // 0 = 正式版(含 .RELEASE 后缀);-1 = 预发布(-M1 / -RC1 / -SNAPSHOT)
        int pre = (rest.isEmpty() || rest.toUpperCase().startsWith(".RELEASE")) ? 0 : -1;
        return new int[]{Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)),
                         Integer.parseInt(m.group(3)), pre};
    }

    /** a 与 b 比较;任一无法解析时抛异常 —— 静默返回 0 会让判定错得没声音。 */
    static int compare(String a, String b) {
        int[] x = parse(a), y = parse(b);
        if (x == null || y == null) {
            throw new IllegalArgumentException("无法解析的版本号: " + (x == null ? a : b));
        }
        for (int i = 0; i < 4; i++) {
            if (x[i] != y[i]) return Integer.compare(x[i], y[i]);
        }
        return 0;
    }

    /** 4.2.4 -> "4.2";解析不了返回 null。 */
    static String line(String v) {
        int[] p = parse(v);
        return p == null ? null : p[0] + "." + p[1];
    }

    private Versions() { }
}
