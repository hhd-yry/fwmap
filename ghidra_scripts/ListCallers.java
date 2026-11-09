// 列出某个函数的调用者（参数是函数名，逗号分隔）。
// 用法：-postScript ListCallers.java "apply_cgi,upgrade"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

public class ListCallers extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] names = getScriptArgs().length > 0 ? getScriptArgs()[0].split(",") : new String[0];
        for (String name : names) {
            SymbolIterator it = currentProgram.getSymbolTable().getSymbols(name);
            boolean found = false;
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s.getSymbolType() != SymbolType.FUNCTION) {
                    continue;
                }
                found = true;
                println("FUNC " + name + " @ " + s.getAddress());
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(s.getAddress());
                int n = 0;
                while (refs.hasNext() && n < 8) {
                    Reference r = refs.next();
                    Function caller = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    println("   <- " + r.getFromAddress() + " in " + (caller == null ? "<none>" : caller.getName()));
                    n++;
                }
            }
            if (!found) {
                println("NOFUNC " + name);
            }
        }
    }
}
