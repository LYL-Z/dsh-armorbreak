import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.File;
import java.io.FileWriter;
import java.io.Writer;

/**
 * ArmorBreak v1.2.0 Ghidra headless export.
 *
 * Emits a bounded function/call summary as JSON. It never decompiles or writes
 * program contents to the workspace; only names/addresses/counts are exported.
 * Run with: -postScript ExportSummary.java <output.json>
 */
public class ExportSummary extends GhidraScript {
    private static String esc(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("ExportSummary needs an output JSON path");
        File out = new File(args[0]);
        FunctionManager fm = currentProgram.getFunctionManager();
        int total = fm.getFunctionCount();
        int limit = 500;
        StringBuilder sb = new StringBuilder(65536);
        sb.append("{\"program\":\"").append(esc(currentProgram.getName())).append("\"")
          .append(",\"language\":\"").append(esc(currentProgram.getLanguageID().toString())).append("\"")
          .append(",\"imageBase\":\"").append(esc(currentProgram.getImageBase().toString())).append("\"")
          .append(",\"functionCount\":").append(total)
          .append(",\"functions\":[");
        int emitted = 0;
        for (Function f : fm.getFunctions(true)) {
            if (emitted >= limit) break;
            if (emitted > 0) sb.append(',');
            ReferenceManager rm = currentProgram.getReferenceManager();
            int calls = 0;
            for (Reference ref : rm.getReferencesTo(f.getEntryPoint())) {
                if (ref.getReferenceType().isCall()) calls += 1;
                if (calls > 200) break;
            }
            sb.append("{\"name\":\"").append(esc(f.getName())).append("\"")
              .append(",\"entry\":\"").append(esc(f.getEntryPoint().toString())).append("\"")
              .append(",\"size\":").append(f.getBody().getNumAddresses())
              .append(",\"external\":").append(f.isExternal())
              .append(",\"thunk\":").append(f.isThunk())
              .append(",\"callingConvention\":\"").append(esc(f.getCallingConventionName())).append("\"")
              .append(",\"callers\":").append(calls)
              .append("}");
            emitted += 1;
        }
        sb.append("],\"emitted\":").append(emitted).append("}");
        try (Writer writer = new FileWriter(out)) {
            writer.write(sb.toString());
        }
        println("ArmorBreak ExportSummary wrote " + emitted + "/" + total + " functions to " + out.getAbsolutePath());
    }
}
