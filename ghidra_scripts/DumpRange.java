// 打印一段地址上的指令（含操作数），用来核对反编译里被折叠掉的常量。
// 用法：-postScript DumpRange.java 0x426b8 0x42710
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class DumpRange extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        Address cur = toAddr(a[0]);
        Address end = toAddr(a[1]);
        while (cur.compareTo(end) < 0 && !monitor.isCancelled()) {
            Instruction ins = currentProgram.getListing().getInstructionAt(cur);
            if (ins == null) {
                cur = cur.add(1);
                continue;
            }
            StringBuilder bytes = new StringBuilder();
            try {
                for (byte b : ins.getBytes()) {
                    bytes.append(String.format("%02x ", b));
                }
            } catch (Exception e) {
                bytes.append("??");
            }
            println(ins.getAddress() + "  " + ins + "    ; " + bytes);
            cur = ins.getMaxAddress().add(1);
        }
    }
}
