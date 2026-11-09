// 按正则列出字符串 + 引用它的函数（用于找 handler 注册点）。
// 用法：-postScript ListStrings.java "telnet|fast_setting"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.regex.Pattern;

public class ListStrings extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        // 参数用逗号分隔多个模式（`|` 会被 cmd 当成管道，别用）
        String pattern = args.length > 0 ? args[0].replace(",", "|") : ".";
        Pattern p = Pattern.compile(pattern);
        int n = 0;
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            if (!d.hasStringValue()) {
                continue;
            }
            String v = d.getValue().toString();
            if (!p.matcher(v).find()) {
                continue;
            }
            n++;
            Address addr = d.getAddress();
            StringBuilder line = new StringBuilder();
            line.append("STR ").append(addr).append("  \"").append(v).append("\"");
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
            int k = 0;
            while (refs.hasNext() && k < 6) {
                Reference r = refs.next();
                Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                String fn = (f == null) ? "<none>" : f.getName() + "(" + f.getEntryPoint() + ")";
                line.append("  <- ").append(r.getFromAddress()).append(" in ").append(fn);
                k++;
            }
            if (k == 0) {
                line.append("  <- (no refs)");
            }
            println(line.toString());
        }
        println("SUMMARY matched=" + n);
    }
}
