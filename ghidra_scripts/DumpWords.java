// 打印一段内存里的 32 位字，并尝试解释成字符串/函数指针。
// 用法：-postScript DumpWords.java 0x52da00 0x52db00
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class DumpWords extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        Address cur = toAddr(a[0]);
        Address end = toAddr(a[1]);
        Memory mem = currentProgram.getMemory();
        while (cur.compareTo(end) < 0 && !monitor.isCancelled()) {
            long v;
            try {
                v = mem.getInt(cur) & 0xffffffffL;
            } catch (Exception e) {
                cur = cur.add(4);
                continue;
            }
            Address t = toAddr(v);
            MemoryBlock blk = t == null ? null : mem.getBlock(t);
            String note = "";
            if (blk != null) {
                Function f = currentProgram.getFunctionManager().getFunctionContaining(t);
                if (f != null) {
                    note = "FUNC " + f.getName();
                } else {
                    Data d = currentProgram.getListing().getDataAt(t);
                    if (d != null && d.hasStringValue()) {
                        note = "STR \"" + d.getValue() + "\"";
                    } else if (blk.isExecute()) {
                        note = "CODE";
                    } else {
                        note = blk.getName();
                    }
                }
            }
            println(cur + "  " + String.format("0x%08x", v) + "  " + note);
            cur = cur.add(4);
        }
    }
}
