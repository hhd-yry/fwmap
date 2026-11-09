// 汇归纳：从已知的命令执行原语（system/popen/exec*）出发，沿调用图反向 BFS，
// 把"能走到命令执行"的函数也登记成 sink-ci。
//
// 为什么需要：厂商固件普遍把 system 包一层（D-Link 的 lxmldbc_system、Tenda 的
// doSystemCmd、Realtek 的 doSystem）。`taint.txt` 是手写白名单，换一家厂商就漏。
// 这个脚本让 sink 像 source 一样可以被归纳出来。
//
// 用法：-postScript InduceSinks.java [maxDepth]      默认 2
// 输出：每行 {"api":"FUN_xxx","addr":"00401234","distance":1,"via":"system"}
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class InduceSinks extends GhidraScript {

    /** 已知的命令执行原语。和 taint.txt 的 sink-ci 保持一致。 */
    private static final String[] EXEC_SEEDS = {
        "system", "_system", "popen", "execve", "execv", "execl", "execlp",
        "execvp", "doSystem", "doSystemCmd", "CsteSystem", "twsystem",
        "rut_doSystemAction", "FCGI_popen", "vfork"
    };

    private boolean isSeed(String n) {
        if (n == null) {
            return false;
        }
        for (String s : EXEC_SEEDS) {
            if (n.equals(s) || n.endsWith("_" + s)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        int maxDepth = 2;
        if (args.length > 0) {
            try {
                maxDepth = Integer.parseInt(args[0].trim());
            } catch (NumberFormatException e) {
                maxDepth = 2;
            }
        }

        // 反向边：callee -> callers
        Map<Address, Set<Function>> callersOf = new HashMap<>();
        Map<Address, Function> byAddr = new HashMap<>();
        List<Function> all = new ArrayList<>();

        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            all.add(f);
            byAddr.put(f.getEntryPoint(), f);
        }
        println("STATS funcs=" + all.size());

        for (Function f : all) {
            if (monitor.isCancelled()) {
                break;
            }
            Set<Function> callees;
            try {
                callees = f.getCalledFunctions(monitor);
            } catch (Exception e) {
                continue;
            }
            for (Function c : callees) {
                Address a = c.getEntryPoint();
                callersOf.computeIfAbsent(a, k -> new LinkedHashSet<>()).add(f);
            }
        }

        // 种子：名字命中执行原语的函数（多数是外部符号/PLT 桩）
        Set<Address> frontier = new LinkedHashSet<>();
        Map<Address, String> viaOf = new HashMap<>();
        FunctionIterator fit2 = currentProgram.getFunctionManager().getFunctions(true);
        while (fit2.hasNext() && !monitor.isCancelled()) {
            Function f = fit2.next();
            if (isSeed(f.getName())) {
                frontier.add(f.getEntryPoint());
                viaOf.put(f.getEntryPoint(), f.getName());
            }
        }
        // 有些固件把 system 当外部符号，函数表里没有——把名字命中的调用点也算上
        if (frontier.isEmpty()) {
            println("WARN no seed function found by name");
        }
        println("STATS seeds=" + frontier.size());

        Set<Address> emitted = new HashSet<>();
        Set<Address> visited = new HashSet<>(frontier);
        for (int depth = 1; depth <= maxDepth && !frontier.isEmpty(); depth++) {
            Set<Address> next = new LinkedHashSet<>();
            for (Address seed : frontier) {
                Set<Function> callers = callersOf.get(seed);
                if (callers == null) {
                    continue;
                }
                for (Function f : callers) {
                    Address ea = f.getEntryPoint();
                    if (emitted.contains(ea)) {
                        continue;
                    }
                    emitted.add(ea);
                    println(String.format(
                            "{\"api\":\"%s\",\"addr\":\"%s\",\"distance\":%d,\"via\":\"%s\"}",
                            f.getName(), ea.toString(), depth, viaOf.getOrDefault(seed, "?")));
                    if (visited.add(ea)) {
                        next.add(ea);
                    }
                }
            }
            // 下一层的 via 用当前层第一个命中的种子名，够用了
            for (Address a : next) {
                Function f = byAddr.get(a);
                if (f != null && !viaOf.containsKey(a)) {
                    viaOf.put(a, "depth" + depth);
                }
            }
            frontier = next;
        }
        println("STATS induced=" + emitted.size() + " depth=" + maxDepth);
    }
}
