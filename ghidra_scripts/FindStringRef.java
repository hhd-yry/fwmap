// 找"引用了某字符串"的函数：给定子串，列出所在字符串、引用点、所属函数。
//
// 用途：确认某个 CVE 的落点函数在不在 M3.1 的池子里（诊断用，不参与判定）。
// 用法：-postScript FindStringRef.java "Invalid Content-Length"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.mem.MemoryAccessException;

import java.util.LinkedHashSet;
import java.util.Set;

public class FindStringRef extends GhidraScript {

    private String readCString(Address a, int max) {
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < max; i++) {
                int b = getByte(a.add(i)) & 0xff;
                if (b == 0) break;
                sb.append((char) b);
            }
        } catch (MemoryAccessException e) {
            return null;
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR usage: FindStringRef.java <substring> [substring...]");
            return;
        }
        Memory mem = currentProgram.getMemory();
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (String needle : args) {
            println("==== needle: " + needle + " ====");
            Set<String> seenFn = new LinkedHashSet<>();
            int hits = 0;
            for (MemoryBlock blk : mem.getBlocks()) {
                // 嵌入式 ELF 经常把 .rodata 放在 RWE 段里，所以不能用 isExecute() 过滤，
                // 否则整个块被跳过 —— 第一版就踩了这个，strings-hit 恒为 0。
                if (!blk.isInitialized()) continue;
                Address start = blk.getStart();
                Address end = blk.getEnd();
                Address a = start;
                StringBuilder cur = new StringBuilder();
                Address curStart = start;
                while (a.compareTo(end) < 0) {
                    int b;
                    try {
                        b = getByte(a) & 0xff;
                    } catch (MemoryAccessException e) {
                        break;
                    }
                    if (b >= 0x20 && b < 0x7f) {
                        if (cur.length() == 0) curStart = a;
                        cur.append((char) b);
                    } else {
                        if (cur.length() >= 4 && cur.toString().contains(needle)) {
                            hits++;
                            String s = cur.toString();
                            for (Reference r : rm.getReferencesTo(curStart)) {
                                Function f = getFunctionContaining(r.getFromAddress());
                                String fn = f == null ? "?" : f.getName();
                                String fa = f == null ? "?" : f.getEntryPoint().toString();
                                if (seenFn.add(fn)) {
                                    println("  fn=" + fn + " @ " + fa +
                                            "  s=\"" + s.substring(0, Math.min(60, s.length())) + "\"");
                                }
                            }
                        }
                        cur.setLength(0);
                    }
                    a = a.add(1);
                }
            }
            println("  strings-hit=" + hits + " functions=" + seenFn.size());
        }
    }
}
