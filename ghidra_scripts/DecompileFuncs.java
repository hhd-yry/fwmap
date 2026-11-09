// 批量反编译指定函数，输出带分隔符的 C 代码，给 M3.2 做函数内数据流。
//
// 用法：-postScript DecompileFuncs.java 0x4012ab,0x401300
//
// 为什么走 C 而不是直接用 p-code：
//   栈变量在 p-code 里是 STORE/LOAD 链，处理起来很啰嗦；在 C 里就是 local_40 这样的名字。
//   代价是脆弱（依赖反编译器的命名），所以 M3.2 的结论只给 low/medium，不给 high。
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileFuncs extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR usage: DecompileFuncs.java <addr,addr,...>");
            return;
        }
        // 地址可能被 shell 拆成多个参数，也可能挤在一个逗号串里——两种都接
        java.util.List<String> targets = new java.util.ArrayList<>();
        for (String a : args) {
            for (String part : a.split(",")) {
                if (!part.trim().isEmpty()) {
                    targets.add(part.trim());
                }
            }
        }
        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.openProgram(currentProgram);

        int ok = 0;
        for (String a : targets) {
            Function f = null;
            Address addr = null;
            try {
                addr = toAddr(a);
            } catch (Exception ignored) {
                // 不是地址，当函数名处理
            }
            if (addr != null) {
                f = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (f == null) {
                    f = currentProgram.getFunctionManager().getFunctionAt(addr);
                }
            }
            if (f == null) {
                // 按名字找（2 跳要反编译 handler 里调用的 helper，只知道名字）
                for (ghidra.program.model.symbol.Symbol s
                        : currentProgram.getSymbolTable().getSymbols(a)) {
                    if (s.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
                        f = currentProgram.getFunctionManager().getFunctionAt(s.getAddress());
                        if (f != null) {
                            break;
                        }
                    }
                }
            }
            if (f == null) {
                println("SKIP " + a + " no-function");
                continue;
            }
            DecompileResults res = ifc.decompileFunction(f, 180, monitor);
            if (!res.decompileCompleted()) {
                println("SKIP " + a + " decompile-failed: " + res.getErrorMessage());
                continue;
            }
            ok++;
            println("===== " + f.getName() + " @ " + f.getEntryPoint() + " =====");
            String c = res.getDecompiledFunction().getC();
            for (String line : resolveDatRefs(c).split("\n")) {
                println("C| " + line);
            }
            println("===== END =====");
        }
        println("SUMMARY decompiled=" + ok);
        ifc.dispose();
    }

    /**
     * 反编译器把短字符串渲染成 &DAT_140004001，参数名就丢了。
     * 这里把这些地址还原成字符串字面量，让下游能直接读到 "cmd" 这样的参数名。
     */
    private String resolveDatRefs(String c) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("&?DAT_([0-9a-fA-F]{6,16})").matcher(c);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String s = readStringAt(m.group(1));
            String rep = s == null ? m.group() : "\"" + s + "\"";
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(rep));
        }
        m.appendTail(sb);

        // MIPS 上还有另一种写法：PTR_s_xxx_<指针地址> + 偏移
        // 真地址 = *(指针地址) + 偏移
        return resolvePtrStrings(resolveBaseOffsets(sb.toString()));
    }

    /**
     * MIPS 的第三种写法：先算一个基址，再用 [基址 + DAT_xxx] 取字符串。
     *
     *     iVar2 = DAT_000a6ad4 + 0xa6a48;          // ← 基址（实测就是 .got 起始）
     *     FUN_xxx(param_1, iVar2 + DAT_000a6ad8)   // ← 字符串 = 基址 + 有符号(该处的字)
     *
     * 三处都要对：基址是"字 + 常量"，偏移是"该地址上的有符号 32 位字"。
     */
    private String resolveBaseOffsets(String c) {
        java.util.Map<String, Long> bases = new java.util.LinkedHashMap<>();
        java.util.regex.Matcher mb = java.util.regex.Pattern.compile(
                "(\\w+)\\s*=\\s*DAT_([0-9a-fA-F]+)\\s*\\+\\s*(0x[0-9a-fA-F]+)\\s*;").matcher(c);
        while (mb.find()) {
            try {
                long w = currentProgram.getMemory().getInt(toAddr(mb.group(2))) & 0xffffffffL;
                bases.put(mb.group(1), w + Long.parseLong(mb.group(3).substring(2), 16));
            } catch (Exception ignored) {
                // 解析不出来就跳过，不编
            }
        }
        for (java.util.Map.Entry<String, Long> en : bases.entrySet()) {
            String var = en.getKey();
            long base = en.getValue();
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                    "\\b" + java.util.regex.Pattern.quote(var) + "\\s*\\+\\s*DAT_([0-9a-fA-F]+)");
            java.util.regex.Matcher m = p.matcher(c);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                String rep = m.group();
                try {
                    int off = currentProgram.getMemory().getInt(toAddr(m.group(1)));   // 有符号
                    String s = readStringAt(Long.toHexString(base + off));
                    if (s != null && !s.isEmpty()) {
                        rep = "\"" + s + "\"";
                    }
                } catch (Exception ignored) {
                    // 同上
                }
                m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(rep));
            }
            m.appendTail(sb);
            c = sb.toString();
        }
        return c;
    }

    private String resolvePtrStrings(String c) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "PTR_[A-Za-z0-9_]*?_([0-9a-fA-F]{6,16})(\\s*\\+\\s*(-?(?:0x)?[0-9a-fA-F]+))?");
        java.util.regex.Matcher m = p.matcher(c);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String rep = m.group();
            try {
                ghidra.program.model.address.Address ptrAddr = toAddr(m.group(1));
                long base = currentProgram.getMemory().getInt(ptrAddr) & 0xffffffffL;
                long delta = 0;
                if (m.group(3) != null) {
                    String t = m.group(3);
                    boolean neg = t.startsWith("-");
                    t = t.replace("-", "").replace("0x", "");
                    delta = Long.parseLong(t, 16);
                    if (neg) {
                        delta = -delta;
                    }
                }
                String s = readStringAt(Long.toHexString(base + delta));
                if (s != null && !s.isEmpty()) {
                    rep = "\"" + s + "\"";
                }
            } catch (Exception e) {
                // 解析不出来就保留原样，不编
            }
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(rep));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String readStringAt(String hex) {
        try {
            ghidra.program.model.address.Address a = toAddr(hex);
            if (a == null || currentProgram.getMemory().getBlock(a) == null) {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 48; i++) {
                byte b = currentProgram.getMemory().getByte(a.add(i));
                if (b == 0) {
                    break;
                }
                if (b < 0x20 || b > 0x7e) {
                    return null;
                }
                sb.append((char) b);
            }
            String s = sb.toString();
            return s.isEmpty() ? null : s;
        } catch (Exception e) {
            return null;
        }
    }
}
