// 在数据段里找「注册表」：连续的 (字符串指针, 函数指针) 对。
// 这类表在嵌入式 web 里就是 URI -> handler 的映射表（websFormDefine 那一类）。
// 用法：-postScript FindRegistrationTable.java [最小连续条数，默认 4]
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import java.util.ArrayList;
import java.util.List;

public class FindRegistrationTable extends GhidraScript {

    @Override
    public void run() throws Exception {
        int minRun = 4;
        String[] args = getScriptArgs();
        if (args.length > 0) {
            minRun = Integer.parseInt(args[0]);
        }

        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized() || b.isExecute()) {
                continue;
            }
            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset();
            List<long[]> run = new ArrayList<>();

            for (long a = start; a + 8 <= end; a += 4) {
                String name = stringAt(ptr(a));
                long fn = ptr(a + 4);
                boolean ok = (name != null) && isCode(fn);
                if (ok) {
                    run.add(new long[] { a, ptr(a), fn });
                } else {
                    flush(run, minRun, b.getName());
                    run.clear();
                }
            }
            flush(run, minRun, b.getName());
        }
    }

    private void flush(List<long[]> run, int minRun, String block) {
        if (run.size() < minRun) {
            return;
        }
        println("TABLE " + block + " entries=" + run.size() + " start=" + toAddr(run.get(0)[0]));
        for (long[] e : run) {
            Address fnAddr = toAddr(e[2]);
            Function f = currentProgram.getFunctionManager().getFunctionContaining(fnAddr);
            String fname = (f == null) ? "<no func>" : f.getName() + " @ " + f.getEntryPoint();
            println("  " + stringAt(e[1]) + "  ->  " + fnAddr + "  " + fname);
        }
        println("ENDTABLE");
    }

    private long ptr(long a) {
        try {
            Address ad = toAddr(a);
            if (ad == null || currentProgram.getMemory().getBlock(ad) == null) {
                return -1;
            }
            return currentProgram.getMemory().getInt(ad) & 0xffffffffL;
        } catch (Exception e) {
            return -1;
        }
    }

    private String stringAt(long a) {
        if (a <= 0) {
            return null;
        }
        Address ad = toAddr(a);
        if (ad == null) {
            return null;
        }
        try {
            Data d = currentProgram.getListing().getDataAt(ad);
            if (d == null || !d.hasStringValue()) {
                return null;
            }
            String v = d.getValue().toString();
            if (v.length() < 2 || v.length() > 64) {
                return null;
            }
            for (char c : v.toCharArray()) {
                if (c < 0x20 || c > 0x7e) {
                    return null;
                }
            }
            return v;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isCode(long a) {
        if (a <= 0) {
            return false;
        }
        Address ad = toAddr(a);
        if (ad == null) {
            return false;
        }
        MemoryBlock b = currentProgram.getMemory().getBlock(ad);
        if (b == null || !b.isExecute()) {
            return false;
        }
        // 有些固件整段都标成可执行，光看 block 属性会把 .rodata 也放进来。
        // 要求目标真的是一条指令、或者落在某个函数里。
        return currentProgram.getListing().getInstructionAt(ad) != null
                || currentProgram.getFunctionManager().getFunctionContaining(ad) != null;
    }
}
