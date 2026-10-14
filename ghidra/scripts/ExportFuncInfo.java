// Exports per-function facts for cross-build alignment: entry, name, name source, size, called functions (in call order)
// and referenced string literals (direct, or one hop through a pointer such as an SH-2 literal-pool entry).
// usage: -postScript ExportFuncInfo.java <out.tsv>   (lines: F addr name source size | C callee | S string)
//@category Scorcher
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class ExportFuncInfo extends GhidraScript {
    Listing lst;
    @Override
    public void run() throws Exception {
        lst = currentProgram.getListing();
        PrintWriter w = new PrintWriter(new FileWriter(getScriptArgs()[0]));
        int nf = 0, ns = 0, nc = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            w.println("F " + f.getEntryPoint() + " " + f.getName() + " " + f.getSymbol().getSource() + " " + f.getBody().getNumAddresses());
            nf++;
            for (Instruction ins : lst.getInstructions(f.getBody(), true)) {
                for (Reference r : ins.getReferencesFrom()) {
                    Address t = r.getToAddress();
                    if (r.getReferenceType().isCall()) {
                        Function c = getFunctionAt(t);
                        if (c != null) { w.println("C " + c.getEntryPoint()); nc++; }
                    } else if (r.getReferenceType().isData() && t.isMemoryAddress()) {
                        String s = stringAt(t);
                        if (s == null) {
                            Data d = lst.getDataContaining(t);
                            if (d != null && d.isPointer() && d.getValue() instanceof Address) s = stringAt((Address) d.getValue());
                            else if (d == null || !d.isDefined()) {
                                try {   // undefined literal-pool slot: read it as a pointer
                                    long v = currentProgram.getMemory().getInt(t) & 0xffffffffL;
                                    Address pt = toAddr(v);
                                    if (currentProgram.getMemory().contains(pt)) s = stringAt(pt);
                                } catch (Exception e) {}
                            }
                        }
                        if (s != null) { w.println("S " + s.replace("\\", "\\\\").replace("\n", "\n").replace("\r", "\r").replace("\t", "\t")); ns++; }
                    }
                }
            }
        }
        w.close();
        println("ExportFuncInfo: " + nf + " functions, " + nc + " calls, " + ns + " string refs");
    }
    String stringAt(Address a) {
        Data d = lst.getDataAt(a);
        if (d != null && d.hasStringValue()) return d.getValue().toString();
        if (d != null && d.isDefined()) return null;
        try {   // undefined bytes: accept a printable, 0-terminated run of 3..120 chars
            byte[] b = new byte[121]; int n = 0;
            while (n < 121) { b[n] = currentProgram.getMemory().getByte(a.add(n)); if (b[n] == 0) break; if (b[n] < 0x20 || b[n] > 0x7e) return null; n++; }
            if (n >= 3 && n < 121) return new String(b, 0, n);
        } catch (Exception e) {}
        return null;
    }
}
