import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ArmorBreak Ghidra 12.1.4 static Program IR export.
 *
 * Emits bounded loader-memory segments, symbols, function locations/hashes,
 * basic blocks and direct call references. It never decompiles, executes, or
 * writes program bytes. Run with:
 * -postScript ExportSummary.java <output.json> [maxFunctions] [maxBlocks]
 *   [maxCallEdges] [maxSymbols]
 */
public class ExportSummary extends GhidraScript {
    private static final int MAX_JSON_CHARS = 4 * 1024 * 1024;
    private static final long MAX_HASH_BYTES_PER_FUNCTION = 256 * 1024;
    private static final long MAX_HASH_BYTES_TOTAL = 16L * 1024 * 1024;

    private static final class FunctionHash {
        String sha256;
        long bytes;
        boolean complete;
        String status;
    }

    private static final class CallEdge {
        String caller;
        String callerEntry;
        String callSite;
        String callSiteFileOffset;
        String callee;
        String calleeEntry;
        String calleeFileOffset;
        String referenceType;
    }

    private static String quote(String value) {
        String input = value == null ? "" : value;
        StringBuilder out = new StringBuilder(input.length() + 2);
        out.append('"');
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        out.append('"');
        return out.toString();
    }

    private static String nullable(String value) {
        return value == null ? "null" : quote(value);
    }

    private static String hex(BigInteger value) {
        return value == null ? null : "0x" + value.toString(16);
    }

    private static String hexOffset(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private static int boundedArg(String[] args, int index, int fallback, int maximum) {
        if (index >= args.length) return fallback;
        try {
            return Math.max(1, Math.min(maximum, Integer.parseInt(args[index])));
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private String fileOffset(Address address) {
        if (address == null || !address.isLoadedMemoryAddress()) return null;
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        if (block == null) return null;
        for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
            if (info.contains(address) && info.getFileBytes().isPresent()) {
                return hexOffset(info.getFileBytesOffset(address));
            }
        }
        return null;
    }

    private String imageRelativeAddress(Address address) {
        if (address == null || address.isExternalAddress()) return null;
        BigInteger relative = address.getOffsetAsBigInteger()
            .subtract(currentProgram.getImageBase().getOffsetAsBigInteger());
        return relative.signum() < 0 ? null : hex(relative);
    }

    private FunctionHash hashFunctionBytes(Function function, long budget) {
        FunctionHash result = new FunctionHash();
        result.sha256 = null;
        result.bytes = 0;
        result.complete = false;
        result.status = "UNAVAILABLE";
        if (function == null || function.isExternal() || budget <= 0) return result;
        try {
            long expected = function.getBody().getNumAddresses();
            long allowed = Math.min(expected, Math.min(MAX_HASH_BYTES_PER_FUNCTION, budget));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            AddressRangeIterator ranges = function.getBody().getAddressRanges(true);
            byte[] chunk = new byte[4096];
            long remaining = allowed;
            while (ranges.hasNext() && remaining > 0) {
                AddressRange range = ranges.next();
                long rangeRemaining = Math.min(range.getLength(), remaining);
                Address cursor = range.getMinAddress();
                while (rangeRemaining > 0) {
                    monitor.checkCancelled();
                    int wanted = (int) Math.min(chunk.length, rangeRemaining);
                    int read = currentProgram.getMemory().getBytes(cursor, chunk, 0, wanted);
                    if (read <= 0) {
                        result.status = "UNAVAILABLE";
                        return result;
                    }
                    digest.update(chunk, 0, read);
                    result.bytes += read;
                    rangeRemaining -= read;
                    remaining -= read;
                    cursor = cursor.add(read);
                }
            }
            if (result.bytes > 0) {
                byte[] hash = digest.digest();
                StringBuilder text = new StringBuilder(hash.length * 2);
                for (byte b : hash) text.append(String.format("%02x", b & 0xff));
                result.sha256 = text.toString();
                result.complete = result.bytes == expected;
                result.status = result.complete ? "COMPLETE" : "PARTIAL_BUDGET";
            }
        } catch (Exception ignored) {
            result.status = "UNAVAILABLE";
        }
        return result;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("ExportSummary needs an output JSON path");
        File out = new File(args[0]).getAbsoluteFile();
        int functionLimit = boundedArg(args, 1, 100, 5000);
        int blockLimit = boundedArg(args, 2, 1000, 5000);
        int edgeLimit = boundedArg(args, 3, 2000, 10000);
        int symbolLimit = boundedArg(args, 4, 1000, 5000);

        FunctionManager manager = currentProgram.getFunctionManager();
        List<Function> functions = new ArrayList<>();
        int internalFunctionCount = 0;
        FunctionIterator functionIterator = manager.getFunctions(true);
        while (functionIterator.hasNext()) {
            monitor.checkCancelled();
            Function function = functionIterator.next();
            if (function.isExternal()) continue;
            internalFunctionCount++;
            if (functions.size() < functionLimit) functions.add(function);
        }
        boolean functionScopeTruncated = internalFunctionCount > functions.size();
        int externalFunctionCount = 0;
        FunctionIterator externalIterator = manager.getExternalFunctions();
        while (externalIterator.hasNext()) {
            monitor.checkCancelled();
            externalIterator.next();
            externalFunctionCount++;
        }

        Map<String, Set<String>> callersByTarget = new HashMap<>();
        Set<String> seenEdges = new HashSet<>();
        List<CallEdge> callEdges = new ArrayList<>();
        boolean callEdgesTruncated = functionScopeTruncated;
        long observedCallEdges = 0;
        long callScanBudget = 1_000_000;
        outerCalls:
        for (Function caller : functions) {
            InstructionIterator instructions = currentProgram.getListing().getInstructions(caller.getBody(), true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = instructions.next();
                for (Reference reference : instruction.getReferencesFrom()) {
                    if (!reference.getReferenceType().isCall()) continue;
                    Function callee = manager.getFunctionAt(reference.getToAddress());
                    if (callee == null) callee = manager.getFunctionContaining(reference.getToAddress());
                    String calleeEntry = callee == null ? reference.getToAddress().toString() : callee.getEntryPoint().toString();
                    String key = caller.getEntryPoint() + "|" + instruction.getMinAddress() + "|" + calleeEntry;
                    if (!seenEdges.add(key)) continue;
                    observedCallEdges++;
                    if (callee != null) {
                        callersByTarget.computeIfAbsent(calleeEntry, ignored -> new HashSet<>()).add(caller.getEntryPoint().toString());
                    }
                    if (callEdges.size() < edgeLimit) {
                        CallEdge edge = new CallEdge();
                        edge.caller = caller.getName();
                        edge.callerEntry = caller.getEntryPoint().toString();
                        edge.callSite = instruction.getMinAddress().toString();
                        edge.callSiteFileOffset = fileOffset(instruction.getMinAddress());
                        edge.callee = callee == null ? "UNRESOLVED" : callee.getName();
                        edge.calleeEntry = calleeEntry;
                        edge.calleeFileOffset = callee == null ? fileOffset(reference.getToAddress()) : fileOffset(callee.getEntryPoint());
                        edge.referenceType = reference.getReferenceType().getName();
                        callEdges.add(edge);
                    } else {
                        callEdgesTruncated = true;
                    }
                    if (observedCallEdges >= callScanBudget) {
                        callEdgesTruncated = true;
                        break outerCalls;
                    }
                }
            }
        }

        List<String> blockJson = new ArrayList<>();
        long basicBlockCount = 0;
        boolean basicBlocksTruncated = functionScopeTruncated;
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        outerBlocks:
        for (Function function : functions) {
            try {
                CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
                while (blocks.hasNext()) {
                    monitor.checkCancelled();
                    CodeBlock block = blocks.next();
                    basicBlockCount++;
                    if (blockJson.size() >= blockLimit) {
                        basicBlocksTruncated = true;
                        break outerBlocks;
                    }
                    Address start = block.getMinAddress();
                    Address end = block.getMaxAddress();
                    blockJson.add("{"
                        + "\"functionEntry\":" + quote(function.getEntryPoint().toString())
                        + ",\"start\":" + quote(start.toString())
                        + ",\"end\":" + quote(end.toString())
                        + ",\"fileOffset\":" + nullable(fileOffset(start))
                        + ",\"size\":" + block.getNumAddresses()
                        + ",\"flowType\":" + quote(String.valueOf(block.getFlowType()))
                        + "}");
                }
            } catch (Exception ignored) {
                /* Preserve other function blocks when one block range is incomplete. */
            }
        }
        if (basicBlocksTruncated) basicBlockCount = Math.max(basicBlockCount, blockJson.size() + 1L);

        List<String> functionJson = new ArrayList<>();
        long totalHashBudget = MAX_HASH_BYTES_TOTAL;
        for (Function function : functions) {
            monitor.checkCancelled();
            FunctionHash hash = hashFunctionBytes(function, totalHashBudget);
            totalHashBudget = Math.max(0, totalHashBudget - hash.bytes);
            Set<String> callers = callersByTarget.get(function.getEntryPoint().toString());
            Address bodyStart = function.getBody().getMinAddress();
            Address bodyEnd = function.getBody().getMaxAddress();
            functionJson.add("{"
                + "\"name\":" + quote(function.getName())
                + ",\"entry\":" + quote(function.getEntryPoint().toString())
                + ",\"relativeAddress\":" + nullable(imageRelativeAddress(function.getEntryPoint()))
                + ",\"fileOffset\":" + nullable(fileOffset(function.getEntryPoint()))
                + ",\"end\":" + nullable(bodyEnd == null ? null : bodyEnd.toString())
                + ",\"size\":" + function.getBody().getNumAddresses()
                + ",\"external\":false"
                + ",\"thunk\":" + function.isThunk()
                + ",\"callingConvention\":" + quote(function.getCallingConventionName())
                + ",\"callers\":" + (callers == null ? 0 : callers.size())
                + ",\"byteHashSha256\":" + nullable(hash.sha256)
                + ",\"byteHashBytes\":" + hash.bytes
                + ",\"byteHashStatus\":" + quote(hash.status)
                + ",\"bodyStart\":" + nullable(bodyStart == null ? null : bodyStart.toString())
                + "}");
        }

        List<String> segmentJson = new ArrayList<>();
        MemoryBlock[] memoryBlocks = currentProgram.getMemory().getBlocks();
        boolean segmentsTruncated = memoryBlocks.length > 256;
        for (int i = 0; i < Math.min(memoryBlocks.length, 256); i++) {
            MemoryBlock block = memoryBlocks[i];
            segmentJson.add("{"
                + "\"name\":" + quote(block.getName())
                + ",\"start\":" + quote(block.getStart().toString())
                + ",\"end\":" + quote(block.getEnd().toString())
                + ",\"fileOffset\":" + nullable(fileOffset(block.getStart()))
                + ",\"size\":" + Long.toUnsignedString(block.getSize())
                + ",\"initialized\":" + block.isInitialized()
                + ",\"read\":" + block.isRead()
                + ",\"write\":" + block.isWrite()
                + ",\"execute\":" + block.isExecute()
                + ",\"overlay\":" + block.isOverlay()
                + ",\"source\":" + nullable(block.getSourceName())
                + "}");
        }

        List<String> symbolJson = new ArrayList<>();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getPrimarySymbolIterator(true);
        long symbolCount = 0;
        boolean symbolsTruncated = false;
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            symbolCount++;
            if (symbolJson.size() >= symbolLimit) {
                symbolsTruncated = true;
                break;
            }
            Address address = symbol.getAddress();
            symbolJson.add("{"
                + "\"name\":" + quote(symbol.getName())
                + ",\"address\":" + quote(address.toString())
                + ",\"fileOffset\":" + nullable(fileOffset(address))
                + ",\"type\":" + quote(String.valueOf(symbol.getSymbolType()))
                + ",\"source\":" + quote(String.valueOf(symbol.getSource()))
                + ",\"external\":" + address.isExternalAddress()
                + "}");
        }

        StringBuilder json = new StringBuilder(65536);
        json.append("{\"program\":").append(quote(currentProgram.getName()))
            .append(",\"executableFormat\":").append(quote(currentProgram.getExecutableFormat()))
            .append(",\"processor\":").append(quote(currentProgram.getLanguage().getProcessor().toString()))
            .append(",\"language\":").append(quote(currentProgram.getLanguageID().toString()))
            .append(",\"endianness\":").append(quote(currentProgram.getLanguage().isBigEndian() ? "big" : "little"))
            .append(",\"toolVersion\":").append(quote(Application.getApplicationVersion()))
            .append(",\"imageBase\":").append(quote(currentProgram.getImageBase().toString()))
            .append(",\"functionCount\":").append(manager.getFunctionCount())
            .append(",\"internalFunctionCount\":").append(internalFunctionCount)
            .append(",\"externalFunctionCount\":").append(externalFunctionCount)
            .append(",\"functionsTruncated\":").append(internalFunctionCount > functionJson.size())
            .append(",\"functions\":[");
        appendJoined(json, functionJson);
        json.append("],\"callEdgeCount\":").append(observedCallEdges)
            .append(",\"callEdgesTruncated\":").append(callEdgesTruncated)
            .append(",\"callEdgeCountComplete\":").append(!callEdgesTruncated)
            .append(",\"callEdges\":[");
        List<String> edgeJson = new ArrayList<>();
        for (CallEdge edge : callEdges) {
            edgeJson.add("{"
                + "\"caller\":" + quote(edge.caller)
                + ",\"callerEntry\":" + quote(edge.callerEntry)
                + ",\"callSite\":" + quote(edge.callSite)
                + ",\"callSiteFileOffset\":" + nullable(edge.callSiteFileOffset)
                + ",\"callee\":" + quote(edge.callee)
                + ",\"calleeEntry\":" + quote(edge.calleeEntry)
                + ",\"calleeFileOffset\":" + nullable(edge.calleeFileOffset)
                + ",\"referenceType\":" + quote(edge.referenceType)
                + "}");
        }
        appendJoined(json, edgeJson);
        json.append("],\"basicBlockCount\":").append(basicBlockCount)
            .append(",\"basicBlocksTruncated\":").append(basicBlocksTruncated)
            .append(",\"basicBlockCountComplete\":").append(!basicBlocksTruncated)
            .append(",\"basicBlocks\":[");
        appendJoined(json, blockJson);
        json.append("],\"segmentsTruncated\":").append(segmentsTruncated)
            .append(",\"segments\":[");
        appendJoined(json, segmentJson);
        json.append("],\"symbolCount\":").append(symbolCount)
            .append(",\"symbolsTruncated\":").append(symbolsTruncated)
            .append(",\"symbols\":[");
        appendJoined(json, symbolJson);
        json.append("]}");
        if (json.length() > MAX_JSON_CHARS) throw new IllegalStateException("ExportSummary result exceeded its 4 MiB hard output cap");
        File parent = out.getParentFile();
        if (parent != null) Files.createDirectories(parent.toPath());
        Files.writeString(out.toPath(), json.toString(), StandardCharsets.UTF_8);
        println("ArmorBreak Ghidra " + Application.getApplicationVersion()
            + " wrote " + functionJson.size() + "/" + internalFunctionCount
            + " internal functions, " + edgeJson.size() + " call edges, " + blockJson.size()
            + " basic blocks to " + out.getAbsolutePath());
    }

    private static void appendJoined(StringBuilder target, List<String> entries) {
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) target.append(',');
            target.append(entries.get(i));
        }
    }
}
