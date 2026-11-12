// M2 策略提取器：输入一个程序，输出 {(uri, handler)}，并标明用的是哪种策略。
//
// 契约（给 Python 侧消费，每行一条 JSON）：
//   {"uri":..., "ref":..., "function":..., "handler":..., "handler_name":..., "strategy":..., "confidence":...}
//
// 两种策略由探测决定，不按厂商写 if-else：
//   registration —— 数据段里的 (名字偏移, handler 偏移) 表；基址靠"哪个候选能让一长串名字都成立"来定
//   strcmp-chain —— 端点字符串在比较链里；判断哪条边是"相等"，顺着它找内联调用
//
// 置信度：注册表命中 medium；比较链直线走到 medium、转过跳转 low；走不到给空 + low，**不猜**。
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.scalar.Scalar;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExtractHandlers extends GhidraScript {

    private boolean debug = false;

    /** 反编译器里的 GOT 槽名：PTR_genacgi_main_004368d8 */
    private static final Pattern PTR_NAME = Pattern.compile(
            "PTR_([A-Za-z_][A-Za-z0-9_]*?)_[0-9a-fA-F]{6,}");

    private DecompInterface decompIfc = null;
    private final Map<String, String> decompCache = new HashMap<>();

    /** 带扩展名的完整路径：/x/y.cgi、/foo.asp、/config.xml */
    private static final Pattern P_PATH_EXT = Pattern.compile(
            "/[A-Za-z0-9_.\\-]+(?:/[A-Za-z0-9_.\\-]+)*\\.(?:cgi|asp|xml|html?)");

    /** 目录式端点：/goform/telnet、/cgi-bin/upgrade */
    private static final Pattern P_DIR = Pattern.compile(
            "/(?:goform|cgi-bin)/[A-Za-z0-9_.\\-]+");

    /** 裸文件名：厂商常把 "upgrade.cgi" 这种不带斜杠的名字直接拿来比较 */
    private static final Pattern P_BARE_EXT = Pattern.compile(
            "(?<![A-Za-z0-9_.\\-/])[A-Za-z0-9_\\-]{2,32}\\.(?:cgi|asp)");

    /** 只有前缀、没有具体名字（uhttpd 那种）：/cgi-bin */
    private static final Pattern P_PREFIX = Pattern.compile(
            "/(?:goform|cgi-bin)(?![A-Za-z0-9_.\\-/])");

    /** 注册表里的 form 名：标识符形状，可带路径分隔符和点，但不能有空格或 %。 */
    private static final Pattern IDENT = Pattern.compile("[A-Za-z0-9_\\-][A-Za-z0-9_\\-./]{1,47}");

    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            if ("debug".equals(a)) {
                debug = true;
            }
        }

        List<Address> strAddrs = new ArrayList<>();
        List<String> uris = new ArrayList<>();
        Set<String> seenUri = new HashSet<>();

        // 1) 收集端点：**匹配到的片段**才是端点，不能把整条字符串当端点
        //    （否则 "http://%s/hndBlock.cgi?..." 这种格式化串会整条混进来）
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            for (Reference r : ins.getReferencesFrom()) {
                Address to = r.getToAddress();
                Data d = currentProgram.getListing().getDataAt(to);
                if (d == null || !d.hasStringValue()) {
                    continue;
                }
                for (String u : endpointsIn(d.getValue().toString())) {
                    if (seenUri.add(u)) {
                        strAddrs.add(to);
                        uris.add(u);
                    }
                }
            }
        }
        println("STATS endpoint_strings=" + strAddrs.size());

        // 1b) 清单补全：有些端点字符串只被数据段引用（表格里），扫指令引用会漏掉。
        //     这里把"所有已定义字符串"过一遍，只补清单，不参与 handler 判定。
        Set<String> emitted = new HashSet<>(uris);
        List<String> extra = new ArrayList<>();
        ghidra.program.model.listing.DataIterator dit =
                currentProgram.getListing().getDefinedData(true);
        int guard = 0;
        while (dit.hasNext() && guard++ < 400000) {
            Data d = dit.next();
            if (!d.hasStringValue()) {
                continue;
            }
            for (String u : endpointsIn(d.getValue().toString())) {
                if (emitted.add(u)) {
                    extra.add(u);
                }
            }
        }
        for (String u : extra) {
            println(json(u, "data", "<data>", "", "", "inventory", "low"));
        }
        if (debug) {
            println("DBG inventory_extra=" + extra.size());
        }

        // 2) 注册表形态
        int tableHits = tryRegistrationTables();

        // 3) 比较链形态
        for (int i = 0; i < strAddrs.size(); i++) {
            Address a = strAddrs.get(i);
            String uri = uris.get(i);
            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
                Function f = currentProgram.getFunctionManager()
                        .getFunctionContaining(r.getFromAddress());
                if (f == null) {
                    continue;          // 数据段里的指针引用，和派发无关
                }
                String strategy = isBarePrefix(uri) ? "prefix"
                        : (usesCompare(f) ? "strcmp-chain" : "unknown");
                if (!isDynamic(uri)) {
                    // 静态页（.asp/.html）由文件服务统一处理，不派发到具体 handler。
                    // 对它们跑分支跟随只会给出假归属（Tenda 上就冒出过 addressNatList.asp -> FUN_xxx）。
                    println(json(uri, r.getFromAddress().toString(), f.getName(), "", "", "inventory", "low"));
                    continue;
                }
                String[] h = handlerFromCompare(f, r.getFromAddress(), uri);
                println(json(uri, r.getFromAddress().toString(), f.getName(), h[0], h[1], strategy, h[2]));
            }
        }
        if (debug) {
            println("DBG table_entries=" + tableHits);
        }
    }

    // ---------------------------------------------------------------- 端点提取

    /** 会被程序派发的端点；静态页不算。 */
    private boolean isDynamic(String uri) {
        return uri.endsWith(".cgi")
                || uri.startsWith("/goform/")
                || uri.startsWith("/cgi-bin/")
                || uri.equals("/goform")
                || uri.equals("/cgi-bin");
    }

    /**
     * 裸前缀（"/cgi-bin"、"/goform"）：这类固件是"前缀 → 一个固定处理函数"，
     * 没有 per-URI handler。标记出来，别假装能定到。
     */
    private boolean isBarePrefix(String uri) {
        return uri.equals("/cgi-bin") || uri.equals("/goform");
    }

    /** 从一条字符串里抽出所有端点片段（长匹配优先，去重）。 */
    private List<String> endpointsIn(String s) {
        List<String> out = new ArrayList<>();
        for (Pattern p : new Pattern[] { P_PATH_EXT, P_DIR, P_BARE_EXT, P_PREFIX }) {
            java.util.regex.Matcher m = p.matcher(s);
            while (m.find()) {
                String v = m.group();
                if (v.length() > 64) {
                    continue;
                }
                boolean covered = false;
                for (String o : out) {
                    if (o.contains(v)) {
                        covered = true;
                        break;
                    }
                }
                if (!covered) {
                    out.add(v);
                }
            }
        }
        // 反过来再去一次：短的可能已经覆盖了长的（前缀优先时会发生）
        List<String> finalOut = new ArrayList<>();
        for (String v : out) {
            boolean covered = false;
            for (String o : out) {
                if (!o.equals(v) && o.contains(v)) {
                    covered = true;
                    break;
                }
            }
            if (!covered) {
                finalOut.add(v);
            }
        }
        return finalOut;
    }

    // ---------------------------------------------------------------- 策略：注册表

    /**
     * 注册表形态：连续的 8 字节记录 (名字偏移, handler 偏移)，两者相对同一个基址。
     *
     * 不写死地址：把每个数据块起点都当候选基址试一遍，哪个基址能让一长串记录
     * 都解析成合法名字，哪个就是真基址。名字直接从内存读（注册表里的名字通常
     * 没人引用，Ghidra 不会给它们建 Data），handler 取 base+偏移 处的指针。
     */
    private int tryRegistrationTables() {
        List<MemoryBlock> blocks = new ArrayList<>();
        List<Long> bases = new ArrayList<>();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized()) {
                continue;
            }
            blocks.add(b);
            String n = b.getName().toLowerCase();
            if (n.contains("got") || n.contains("data") || n.contains("rodata")) {
                bases.add(b.getStart().getOffset());
            }
        }
        if (debug) {
            println("DBG blocks=" + blocks.size() + " bases=" + bases.size());
        }

        Set<String> seen = new HashSet<>();
        int emitted = 0;
        int nameHits = 0;
        int handlerHits = 0;

        // 每个 (block, base) 都能凑出"看起来像表"的片段，但只有一个是真基址。
        // 判据：真表的 handler 名字通常和 form 名相似（aspXxx / formXxx / fromXxx）。
        // 所以按"名字相似度 + 条数"给每段打分，只输出得分最高的那几段。
        List<Object[]> candidates = new ArrayList<>();   // {score(float), run(List<String[])>}

        for (MemoryBlock b : blocks) {
            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset();
            if (end - start > 4 << 20) {
                continue;
            }
            for (long base : bases) {
                List<String[]> run = new ArrayList<>();
                long a = start;
                while (a + 8 <= end) {
                    String name = readIdent(base + readInt(a));
                    String[] hh = name == null ? new String[] { "", "" }
                            : resolveHandler(base + readInt(a + 4));
                    String handler = hh[1];
                    if (name == null || handler.isEmpty()) {
                        keep(candidates, run);
                        run = new ArrayList<>();
                        a += 4;
                        continue;
                    }
                    if (name != null) {
                        nameHits++;
                        handlerHits++;
                    }
                    run.add(new String[] { name, handler, hh[0] });
                    a += 8;      // 记录是 8 字节，命中后要整条跳过，否则第二半会被当成名字
                }
                keep(candidates, run);
            }
        }

        if (debug) {
            println("DBG name_hits=" + nameHits + " handler_hits=" + handlerHits
                    + " candidates=" + candidates.size());
        }

        candidates.sort((x, y) -> Float.compare((Float) y[0], (Float) x[0]));
        for (int i = 0; i < Math.min(3, candidates.size()); i++) {
            @SuppressWarnings("unchecked")
            List<String[]> best = (List<String[]>) candidates.get(i)[1];
            if (best.size() < 4) {
                continue;
            }
            if (debug) {
                println("DBG table score=" + candidates.get(i)[0] + " size=" + best.size());
            }
            for (String[] r : best) {
                String key = r[0] + "|" + r[1];
                if (seen.add(key)) {
                    println(json(r[0], "table", "<table>", r[2], r[1], "registration", "medium"));
                    emitted++;
                }
            }
        }
        return emitted;
    }

    /** 记录一段候选表，打分 = 条数 × (1 + 名字相似比例)。 */
    private void keep(List<Object[]> candidates, List<String[]> run) {
        // 太短的段不可信：Linksys 上就冒出过一条 4 条的假表（名字 "2ND"）。
        if (run.size() < 5) {
            return;
        }
        int similar = 0;
        for (String[] r : run) {
            String n = r[0].toLowerCase();
            String h = r[1].toLowerCase();
            if (h.contains(n) || n.contains(h) || sharePrefix(n, h)) {
                similar++;
            }
        }
        float ratio = (float) similar / run.size();
        // 真表的 handler 和 form 名几乎总是同源（aspXxx/formXxx/fromXxx）；假表不会。
        if (ratio < 0.3f) {
            return;
        }
        float score = run.size() * (1.0f + ratio);
        candidates.add(new Object[] { score, run });
    }

    private boolean sharePrefix(String a, String b) {
        int n = Math.min(a.length(), b.length());
        int i = 0;
        while (i < n && a.charAt(i) == b.charAt(i)) {
            i++;
        }
        return i >= 4;
    }

    /** 从 addr 读一个 C 字符串，要求是标识符形状。 */
    private String readIdent(long addr) {
        if (addr <= 0) {
            return null;
        }
        Address a = toAddr(addr);
        MemoryBlock blk = a == null ? null : currentProgram.getMemory().getBlock(a);
        if (blk == null || !blk.isInitialized()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 48; i++) {
            byte v;
            try {
                v = currentProgram.getMemory().getByte(a.add(i));
            } catch (Exception e) {
                return null;
            }
            if (v == 0) {
                break;
            }
            if (v < 0x21 || v > 0x7e) {
                return null;
            }
            sb.append((char) v);
        }
        String s = sb.toString();
        // 不卡标识符形状的话，.rodata 里连成片的错误消息会把整张表淹掉（实测 1483 条假阳性）
        return IDENT.matcher(s).matches() ? s : null;
    }

    /** base+偏移 处的字指向哪个函数（GOT 槽里存的是真实地址）。返回 {地址, 函数名}。 */
    private String[] resolveHandler(long addr) {
        if (addr <= 0) {
            return new String[] { "", "" };
        }
        Address a = toAddr(addr);
        MemoryBlock blk = a == null ? null : currentProgram.getMemory().getBlock(a);
        if (blk == null || !blk.isInitialized()) {
            return new String[] { "", "" };
        }
        int v = readInt(addr);
        Address t = toAddr(v);
        MemoryBlock tb = t == null ? null : currentProgram.getMemory().getBlock(t);
        if (tb == null) {
            return new String[] { "", "" };
        }
        Function f = currentProgram.getFunctionManager().getFunctionAt(t);
        if (f != null) {
            return new String[] { t.toString(), f.getName() };
        }
        Function c = currentProgram.getFunctionManager().getFunctionContaining(t);
        return c == null ? new String[] { "", "" } : new String[] { t.toString(), c.getName() };
    }

    private int readInt(long addr) {
        try {
            return currentProgram.getMemory().getInt(toAddr(addr));
        } catch (Exception e) {
            return 0;
        }
    }

    // ---------------------------------------------------------------- 策略：比较链

    /** 函数里有没有调用 strcmp 一类（决定策略标签）。 */
    private boolean usesCompare(Function f) {
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            String n = callTargetName(it.next());
            if (n != null && (n.startsWith("strcmp") || n.startsWith("strncmp")
                    || n.startsWith("strcasecmp") || n.startsWith("strstr"))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 比较链形态：从字符串引用点找出比较调用，判断哪条边是"相等"，顺着它找内联调用。
     *
     * MIPS 的典型写法：
     *     jalr t9                 ; strcmp(uri, "x.cgi")
     *     bne  v0,zero,<不等跳>    ; != 0 就跳走
     *     ...                     ; 相等路径继续
     */
    private String[] handlerFromCompare(Function f, Address from, String uri) {
        Instruction ins = currentProgram.getListing().getInstructionAt(from);
        if (ins == null) {
            return giveUp(uri, "no-instruction");
        }

        Instruction call = null;
        // 先认"用这个字符串的那次比较调用"。
        //
        // MIPS 上字符串地址经常在**延迟槽里**才拼完：
        //     jalr t9                    ; strcmp
        //     addiu a1,a1,0x1fa8         ; ← 引用在这里（延迟槽，先于 jalr 生效）
        //     bne  v0,zero,next
        // 只往后找会把**下一条** strcmp 当成这次比较，整条链错位一格
        // （D-Link 上就表现为 gena.cgi -> wfadev_main）。
        // 所以前后各看几条，取距离最近的调用。
        Instruction back = ins;
        int backDist = -1;
        for (int i = 0; i < 5 && back != null; i++) {
            if (isCall(back)) {
                backDist = i;
                break;
            }
            back = currentProgram.getListing().getInstructionBefore(back.getAddress());
        }
        Instruction fwd = ins;
        int fwdDist = -1;
        for (int i = 0; i < 6 && fwd != null; i++) {
            if (isCall(fwd)) {
                fwdDist = i;
                break;
            }
            fwd = currentProgram.getListing().getInstructionAfter(fwd.getAddress());
        }
        if (backDist >= 0 && (fwdDist < 0 || backDist < fwdDist)) {
            call = back;
        } else if (fwdDist >= 0) {
            call = fwd;
        }
        if (call == null) {
            return giveUp(uri, "no-compare-call");
        }

        Instruction br = null;
        Instruction p = call;
        for (int i = 0; i < 10 && p != null; i++) {
            p = currentProgram.getListing().getInstructionAfter(p.getAddress());
            if (p == null) {
                break;
            }
            if (p.getFlowType().isConditional()) {
                br = p;
                break;
            }
        }
        if (br == null) {
            return giveUp(uri, "no-branch");
        }

        Address edge = equalityEdge(br);
        if (edge == null) {
            return giveUp(uri, "no-equality-edge");
        }

        boolean jumped = false;
        Address cur = edge;
        Set<Address> seen = new HashSet<>();
        for (int step = 0; step < 40 && cur != null; step++) {
            if (!seen.add(cur)) {
                break;
            }
            Instruction in = currentProgram.getListing().getInstructionAt(cur);
            if (in == null) {
                break;
            }
            Address ca = callAddr(in);
            if (ca != null) {
                Function target = currentProgram.getFunctionManager().getFunctionAt(ca);
                if (target != null && !target.isThunk() && !target.isExternal()) {
                    return new String[] {
                            target.getEntryPoint().toString(),
                            target.getName(),
                            jumped ? "low" : "medium" };
                }
            }
            // 第二种写法：相等边上不直接 call，而是把 GOT 里的函数指针存进跳板变量，
            // 整条比较链走完后再统一 `jalr`。D-Link / Netgear / Linksys 的 CGI 多路复用器
            // 几乎都是这样，只认直接 call 会一路 giveUp。
            if (in.getFlowType().isTerminal()) {
                break;
            }
            if (in.getFlowType().isJump()) {
                Address[] flows = in.getFlows();
                if (flows.length == 0) {
                    break;
                }
                cur = flows[0];
                jumped = true;
                continue;
            }
            cur = in.getAddress().add(in.getLength());
        }
        // 指令层走不通时，交给反编译器再试一次（GOT 函数指针派发）
        String[] dh = handlerFromDecompiled(f, uri);
        if (dh != null) {
            return dh;
        }
        return giveUp(uri, "walked-no-internal-call");
    }

    private String[] giveUp(String uri, String reason) {
        if (debug) {
            println("DBG " + uri + " " + reason);
        }
        return new String[] { "", "", "low" };
    }

    /** 是不是一次调用：直接 call，或者 MIPS 的 jal / jalr。 */
    private boolean isCall(Instruction ins) {
        if (ins == null) {
            return false;
        }
        return callAddr(ins) != null
                || ins.getMnemonicString().toLowerCase().startsWith("jal");
    }

    /**
     * 兜底：用反编译器解析"相等边赋 GOT 函数指针、链尾统一间接调用"的写法。
     *
     * 为什么不在指令层做：MIPS 里 `lw t9,-0x7f48(gp)` 的 gp 是运行时从栈上恢复的
     * （每次调用后 `lw gp,0x10(sp)`），静态按 _gp0 推算会算到别的槽上——实测在
     * D-Link cgibin 上会把 27 个端点全指到 dlsyslog_main。反编译器自己跟踪了 gp，
     * 它已经把槽名解析成 PTR_genacgi_main_004368d8，直接用它更可靠。
     *
     * 形态（反编译后）：
     *     iVar1 = strcmp(param1,"gena.cgi");
     *     if (iVar1 == 0) {
     *         UNRECOVERED_JUMPTABLE = (code *)PTR_genacgi_main_004368d8;
     *     }
     */
    private String[] handlerFromDecompiled(Function f, String uri) {
        String c = decompileC(f);
        if (c == null) {
            return null;
        }
        String[] lines = c.split("\n");
        String needle = "\"" + uri + "\"";
        for (int i = 0; i < lines.length; i++) {
            if (!lines[i].contains("strcmp") || !lines[i].contains(needle)) {
                continue;
            }
            for (int j = i + 1; j < Math.min(lines.length, i + 14); j++) {
                Matcher m = PTR_NAME.matcher(lines[j]);
                if (!m.find()) {
                    continue;
                }
                String fn = m.group(1);
                Address a = addrOfFunction(fn);
                if (a != null) {
                    return new String[] { a.toString(), fn, "medium" };
                }
            }
        }
        return null;
    }

    /** 按名字找本程序里的函数入口。 */
    private Address addrOfFunction(String name) {
        SymbolIterator sit = currentProgram.getSymbolTable().getSymbols(name);
        while (sit.hasNext()) {
            Symbol s = sit.next();
            if (s.getSymbolType() != SymbolType.FUNCTION) {
                continue;
            }
            Function f = currentProgram.getFunctionManager().getFunctionAt(s.getAddress());
            if (f != null && !f.isExternal() && !f.isThunk()) {
                return f.getEntryPoint();
            }
        }
        return null;
    }

    /** 反编译一个函数，带缓存（同一个函数里的多个端点只解一次）。 */
    private String decompileC(Function f) {
        String key = f.getEntryPoint().toString();
        if (decompCache.containsKey(key)) {
            return decompCache.get(key);
        }
        String out = null;
        try {
            if (decompIfc == null) {
                decompIfc = new DecompInterface();
                decompIfc.toggleCCode(true);
                decompIfc.openProgram(currentProgram);
            }
            DecompileResults r = decompIfc.decompileFunction(f, 60, monitor);
            if (r != null && r.decompileCompleted()) {
                out = r.getDecompiledFunction().getC();
            }
        } catch (Exception e) {
            if (debug) {
                println("DBG decompile fail " + key + " " + e.getMessage());
            }
        }
        decompCache.put(key, out);
        return out;
    }

    /**
     * strcmp 的返回值在哪条边表示"相等"。只认语义，不绑指令：
     *   beq / je / jz   -> 相等走分支目标
     *   bne / jne / jnz -> 相等走 fall-through（MIPS 还要跨过 delay slot）
     */
    private Address equalityEdge(Instruction br) {
        String m = br.getMnemonicString().toLowerCase();
        boolean onEqual = m.startsWith("beq") || m.equals("je") || m.equals("jz");
        boolean onNotEqual = m.startsWith("bne") || m.equals("jne") || m.equals("jnz");
        if (onEqual) {
            Address[] flows = br.getFlows();
            return flows.length > 0 ? flows[0] : null;
        }
        if (!onNotEqual) {
            return null;
        }
        Address fall = br.getFallThrough();
        if (fall == null) {
            return null;
        }
        if (!isMips()) {
            return fall;
        }
        Instruction delay = currentProgram.getListing().getInstructionAt(fall);
        if (delay == null) {
            return fall;
        }
        Instruction after = currentProgram.getListing().getInstructionAfter(delay.getAddress());
        return after == null ? null : after.getAddress();
    }

    private boolean isMips() {
        return currentProgram.getLanguage().getProcessor().toString()
                .toLowerCase().contains("mips");
    }

    // ---------------------------------------------------------------- 调用解析

    private Address callAddr(Instruction ins) {
        for (PcodeOp op : ins.getPcode()) {
            if (op.getOpcode() == PcodeOp.CALL) {
                Varnode v = op.getInput(0);
                if (v != null && v.isAddress()) {
                    return v.getAddress();
                }
            }
        }
        return null;
    }

    /**
     * MIPS 上库函数都是 `lw t9,-X(gp); jalr t9`，CALL 的操作数是寄存器。
     * 往回找几条指令，把 GOT 槽解成函数名。
     */
    private String resolveIndirectName(Instruction call) {
        Instruction p = call;
        for (int i = 0; i < 8 && p != null; i++) {
            p = currentProgram.getListing().getInstructionBefore(p.getAddress());
            if (p == null) {
                return null;
            }
            for (Reference r : p.getReferencesFrom()) {
                String n = nameAt(r.getToAddress());
                if (n != null) {
                    return n;
                }
            }
        }
        return null;
    }

    private String callTargetName(Instruction ins) {
        Address t = callAddr(ins);
        if (t != null) {
            String n = nameAt(t);
            if (n != null) {
                return n;
            }
        }
        return resolveIndirectName(ins);
    }

    /** 地址 -> 函数名：本程序函数 / 符号 / GOT 里存的指针。 */
    private String nameAt(Address a) {
        if (a == null) {
            return null;
        }
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f != null && f.isThunk()) {
            Function t = f.getThunkedFunction(true);
            if (t != null) {
                return t.getName();
            }
        }
        if (f != null) {
            return f.getName();
        }
        for (Symbol s : currentProgram.getSymbolTable().getSymbols(a)) {
            if (s.getSymbolType() == SymbolType.FUNCTION) {
                return s.getName();
            }
        }
        Data d = currentProgram.getListing().getDataAt(a);
        if (d != null && d.getValue() instanceof Address) {
            Address t = (Address) d.getValue();
            Function tf = currentProgram.getFunctionManager().getFunctionAt(t);
            if (tf != null) {
                return tf.getName();
            }
        }
        return null;
    }

    // ---------------------------------------------------------------- 输出

    private String json(String uri, String ref, String fn, String handler, String hname,
                        String strategy, String conf) {
        return String.format(
                "{\"uri\":\"%s\",\"ref\":\"%s\",\"function\":\"%s\",\"handler\":\"%s\","
                        + "\"handler_name\":\"%s\",\"strategy\":\"%s\",\"confidence\":\"%s\"}",
                esc(uri), esc(ref), esc(fn), esc(handler), esc(hname), strategy, conf);
    }

    private String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }
}
