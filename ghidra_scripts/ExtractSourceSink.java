// M3.1：把每个函数里的「源调用」和「汇调用」抽出来。
//
// 用法：-postScript ExtractSourceSink.java <taint.txt 的路径>
//
// 输出（每行一条 JSON）：
//   {"function":..., "address":..., "sources":[{api,param,at,weak}], "sinks":[{api,category,at}]}
//
// 只做检索，不做判断：
//   汇是符号问题（规则接近 100%），源只是"候选"——最终是不是外部可控，要靠 M3.2 的数据流和 M3.3 的语义。
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExtractSourceSink extends GhidraScript {

    private final Map<String, String> sources = new HashMap<>();   // name -> "source" / "weak"
    private final Map<String, String> sinks = new HashMap<>();     // name -> ci/bof/fmt

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR usage: ExtractSourceSink.java <taint.txt> [out.jsonl]");
            return;
        }
        loadCatalog(args[0]);
        println("STATS sources=" + sources.size() + " sinks=" + sinks.size());

        // 行可能很长（源调用多），走 headless 的 stdout 会被拆行，下游 JSON 解析会静默丢记录。
        // 所以直接写文件。
        java.io.PrintWriter out = null;
        if (args.length >= 2) {
            out = new java.io.PrintWriter(new java.io.BufferedWriter(
                    new java.io.FileWriter(args[1])));
        }

        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        int funcs = 0;
        int withSrc = 0;
        int withSink = 0;
        int withBoth = 0;

        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            if (f.isThunk() || f.isExternal()) {
                continue;
            }
            funcs++;
            List<String> src = new ArrayList<>();
            List<String> snk = new ArrayList<>();

            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                String name = callTargetName(ins);
                if (name == null) {
                    continue;
                }
                String kind = sources.get(name);
                if (kind != null) {
                    String param = stringArgBefore(ins);
                    src.add("{\"api\":\"" + esc(name) + "\",\"param\":\"" + esc(param)
                            + "\",\"at\":\"" + ins.getAddress() + "\",\"weak\":"
                            + ("weak".equals(kind) ? "true" : "false") + "}");
                    continue;
                }
                String cat = sinks.get(name);
                if (cat != null) {
                    snk.add("{\"api\":\"" + esc(name) + "\",\"category\":\"" + cat
                            + "\",\"at\":\"" + ins.getAddress() + "\"}");
                }
            }

            if (src.isEmpty() && snk.isEmpty()) {
                continue;
            }
            if (!src.isEmpty()) {
                withSrc++;
            }
            if (!snk.isEmpty()) {
                withSink++;
            }
            if (!src.isEmpty() && !snk.isEmpty()) {
                withBoth++;
            }
            String line = "{\"function\":\"" + esc(f.getName()) + "\",\"address\":\""
                    + f.getEntryPoint() + "\",\"sources\":[" + String.join(",", src)
                    + "],\"sinks\":[" + String.join(",", snk) + "]}";
            if (out != null) {
                out.println(line);
            } else {
                println(line);
            }
        }
        if (out != null) {
            out.close();
        }
        println("SUMMARY funcs=" + funcs + " with_source=" + withSrc
                + " with_sink=" + withSink + " with_both=" + withBoth);
    }

    // ---------------------------------------------------------------- 目录

    private void loadCatalog(String path) throws Exception {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\\s+");
                if (parts.length < 2) {
                    continue;
                }
                String kind = parts[0];
                String name = parts[parts.length - 1];
                if (kind.startsWith("source")) {
                    // 只认过 "source" / "source-weak" 两种。加了 source-induced 之后
                    // 这两个等号判断会**静默忽略**新类别——正是本项目反复踩的
                    // "少东西但不报错"。改成前缀判断，以后再加细分不会有同样的问题。
                    // 注意：weak 只由 "source-weak" 决定；induced 是在 Python 侧
                    // （m3flow.INDUCED_SOURCES）判的，这里不能丢。
                    sources.put(name, kind.equals("source-weak") ? "weak" : "strong");
                } else if (kind.startsWith("sink-")) {
                    sinks.put(name, kind.substring(5));
                }
            }
        }
    }

    // ---------------------------------------------------------------- 调用解析（与 M2 同款）

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

    private String callTargetName(Instruction ins) {
        Address t = callAddr(ins);
        if (t != null) {
            String n = nameAt(t);
            if (n != null) {
                return n;
            }
        }
        // 间接调用：往回找 GOT 槽
        Instruction p = ins;
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

    private String nameAt(Address a) {
        if (a == null) {
            return null;
        }
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f != null) {
            if (f.isThunk()) {
                Function t = f.getThunkedFunction(true);
                if (t != null) {
                    return t.getName();
                }
            }
            return f.getName();
        }
        for (Symbol s : currentProgram.getSymbolTable().getSymbols(a)) {
            if (s.getSymbolType() == SymbolType.FUNCTION) {
                return s.getName();
            }
        }
        Data d = currentProgram.getListing().getDataAt(a);
        if (d != null && d.getValue() instanceof Address) {
            Function tf = currentProgram.getFunctionManager().getFunctionAt((Address) d.getValue());
            if (tf != null) {
                return tf.getName();
            }
        }
        return null;
    }

    /**
     * 源调用的参数名：往回几条指令找字符串引用。
     * websGetVar(wp, "usbName", ...) 的第二个参数就是这么来的——启发式，但不是猜。
     */
    private String stringArgBefore(Instruction call) {
        Instruction p = call;
        for (int i = 0; i < 6 && p != null; i++) {
            p = currentProgram.getListing().getInstructionBefore(p.getAddress());
            if (p == null) {
                return "";
            }
            for (Reference r : p.getReferencesFrom()) {
                Data d = currentProgram.getListing().getDataAt(r.getToAddress());
                if (d != null && d.hasStringValue()) {
                    String s = d.getValue().toString();
                    if (s.length() >= 1 && s.length() <= 48) {
                        return s;
                    }
                }
            }
        }
        return "";
    }

    private String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(' ');
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
