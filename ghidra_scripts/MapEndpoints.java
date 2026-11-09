// M2 的最小闭环：端点字符串 → 引用它的函数。
// 用法：analyzeHeadless <proj> <name> -process <file> -noanalysis
//        -scriptPath <dir> -postScript MapEndpoints.java
// 输出每行：端点字符串 | 引用地址 | 所在函数 | 是否为函数入口
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.LinkedHashSet;
import java.util.Set;

public class MapEndpoints extends GhidraScript {

    private static final String[] PREFIXES = { "/goform/", "/cgi-bin/", ".cgi" };

    @Override
    public void run() throws Exception {
        int hits = 0;
        int strings = 0;
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            if (!d.hasStringValue()) {
                continue;
            }
            String v = d.getValue().toString();
            if (!looksLikeEndpoint(v)) {
                continue;
            }
            strings++;
            Address addr = d.getAddress();
            Set<String> seen = new LinkedHashSet<>();
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
            while (refs.hasNext()) {
                Reference r = refs.next();
                Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                String fname = (f == null) ? "<no function>" : f.getName() + " @ " + f.getEntryPoint();
                String line = v + " | ref " + r.getFromAddress() + " | " + fname
                        + " | entry=" + (f != null && f.getEntryPoint().equals(r.getFromAddress()));
                if (seen.add(line)) {
                    println("ENDPOINT " + line);
                    hits++;
                }
            }
        }
        println("SUMMARY strings=" + strings + " refs=" + hits);
    }

    private boolean looksLikeEndpoint(String v) {
        for (String p : PREFIXES) {
            if (v.contains(p)) {
                return true;
            }
        }
        return false;
    }
}
