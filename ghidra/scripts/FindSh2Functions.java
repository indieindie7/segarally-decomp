// Creates functions at SH-2 prologues that follow an "rts; <delay slot>" pair inside the code regions
// of LORT.BIN, where Ghidra's flow analysis did not reach. Run before a normal analysis pass.
//@category Scorcher
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public class FindSh2Functions extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[][] ranges = {{0x06004000L, 0x0603E980L}};
        Memory mem = currentProgram.getMemory();
        int made = 0, seen = 0;
        for (long[] r : ranges) {
            for (long a = r[0] + 4; a < r[1] - 4; a += 2) {
                Address addr = toAddr(a);
                int w = mem.getShort(addr) & 0xffff;
                boolean prologue = (w == 0x2FE6) || (w == 0x4F22) || (w == 0x2F86) || (w == 0x2FD6) || (w == 0x2FC6) || (w == 0x2FB6) || (w == 0x2FA6) || (w == 0x2F96);
                if (!prologue) continue;
                int prev2 = mem.getShort(addr.subtract(4)) & 0xffff;   // instruction before the delay slot
                boolean afterRts = (prev2 == 0x000B);
                // also accept a literal-pool gap: previous words look like an address into this program
                if (!afterRts) {
                    int lit = mem.getInt(addr.subtract(4));
                    afterRts = (lit >= 0x06004000 && lit < 0x06100000) && (a % 4 == 0);
                }
                if (!afterRts) continue;
                seen++;
                if (getFunctionContaining(addr) != null || getInstructionAt(addr) != null) continue;
                disassemble(addr);
                if (createFunction(addr, null) != null) made++;
            }
        }
        println("prologue candidates " + seen + ", new functions " + made);
    }
}
