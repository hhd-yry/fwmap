// 反编译指定地址所在的函数，打印 C 伪代码。
// 用法：-postScript DecompileAt.java 0x2f194 0x2a720
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileAt extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        ifc.openProgram(currentProgram);

        for (String arg : getScriptArgs()) {
            Address a = toAddr(arg);
            Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
            if (f == null) {
                println("NOFUNC " + arg);
                continue;
            }
            println("===== " + f.getName() + " @ " + f.getEntryPoint() + " =====");
            DecompileResults res = ifc.decompileFunction(f, 120, monitor);
            if (!res.decompileCompleted()) {
                println("DECOMP FAILED " + res.getErrorMessage());
                continue;
            }
            println(res.getDecompiledFunction().getC());
            println("===== END " + f.getName() + " =====");
        }
        ifc.dispose();
    }
}
