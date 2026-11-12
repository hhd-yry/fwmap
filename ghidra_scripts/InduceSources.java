// 框架归纳：从二进制里找"取参 API"——被很多调用点用不同字符串常量调用的函数。
//
// 形状（get_cgi("lan_ip")）：
//     ldr r0, ="/lan_ip" ; bl get_cgi
// 判据：被 ≥5 个不同调用点调用，且这些调用点用的是 ≥3 个不同的字符串常量。
//
// 输出（每行一条 JSON）：
//   {"api":"get_cgi","address":"0x...","calls":42,"distinct":17,"strings":["lan_ip",...]}
//
// 这一步不需要 LLM：证据是结构性的（调用次数、字符串常量、参数位置），规则一眼能看出来。
// LLM 该用在下一层——判断"这个 API 读的是用户输入还是配置"。
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

public class InduceSources extends GhidraScript {

    @Override
    public void run() throws Exception {
        int minCalls = 5;
        int minDistinct = 3;
        String[] args = getScriptArgs();
        if (args.length >= 2) {
            minCalls = Integer.parseInt(args[0]);
            minDistinct = Integer.parseInt(args[1]);
        }

        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        TreeMap<String, List<String>> found = new TreeMap<>();

        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            // 库函数不是厂商的取参 API——它们只是在别处被调用时"附近有字符串"
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            Address ep = f.getEntryPoint();
            List<String> callStrings = new ArrayList<>();
            int calls = 0;

            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(ep)) {
                if (!r.getReferenceType().isCall() && !r.getReferenceType().isJump()) {
                    continue;
                }
                calls++;
                String s = stringArgNear(r.getFromAddress());
                if (s != null) {
                    callStrings.add(s);
                }
            }
            if (calls < minCalls) {
                continue;
            }
            Set<String> distinct = new LinkedHashSet<>(callStrings);
            if (distinct.size() < minDistinct) {
                continue;
            }
            List<String> sample = new ArrayList<>(distinct).subList(0, Math.min(12, distinct.size()));
            found.put(f.getName(), sample);
            println(String.format(
                    "{\"api\":\"%s\",\"address\":\"%s\",\"calls\":%d,\"distinct\":%d,\"strings\":[%s]}",
                    esc(f.getName()), ep, calls, distinct.size(),
                    "\"" + String.join("\",\"", sample) + "\""));
        }
        println("SUMMARY induced=" + found.size());
    }

    /** 调用点附近（往回 3 条指令）被引用的字符串常量。 */
    private String stringArgNear(Address from) {
        Instruction p = currentProgram.getListing().getInstructionAt(from);
        for (int i = 0; i < 3 && p != null; i++) {
            p = currentProgram.getListing().getInstructionBefore(p.getAddress());
            if (p == null) {
                return null;
            }
            for (Reference r : p.getReferencesFrom()) {
                Data d = currentProgram.getListing().getDataAt(r.getToAddress());
                if (d != null && d.hasStringValue()) {
                    String s = d.getValue().toString();
                    // 参数名长得像标识符：没有空格、没有 %、不太长。
                    // 不加这条，错误消息（"Bad handle %d"、"HTTP/1.0 200 OK"）会把候选表糊满。
                    if (s.length() >= 2 && s.length() <= 32 && s.matches("[A-Za-z0-9_.\\-/]+")) {
                        return s;
                    }
                }
            }
        }
        return null;
    }

    private String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }
}
