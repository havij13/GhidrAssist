package ghidrassist.graphrag.extraction;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Desktop Sigga-aligned function signature generator.
 * Mirrors the reference implementation's masking, tiering, and uniqueness checks.
 */
public class FunctionSignatureGenerator {

    private static final int MAX_INSTRUCTIONS_TO_SCAN = 200;
    private static final int MIN_WINDOW_BYTES = 5;
    private static final int MAX_WINDOW_BYTES = 128;
    private static final int XREF_CONTEXT_INSTRUCTIONS = 8;
    private static final int MAX_START_OFFSET = 64;

    private final Program program;
    private final TaskMonitor monitor;

    private enum MaskProfile {
        STRICT,
        MINIMAL
    }

    private static final class SigResult {
        private final String signature;

        private SigResult(String signature) {
            this.signature = signature;
        }
    }

    private static final class TokenData {
        private final List<String> tokens;
        private final Set<Integer> instructionStartIndices;

        private TokenData(List<String> tokens, Set<Integer> instructionStartIndices) {
            this.tokens = tokens;
            this.instructionStartIndices = instructionStartIndices;
        }
    }

    private static final class ByteSignature {
        private final byte[] bytes;
        private final byte[] mask;

        private ByteSignature(String signature) {
            String[] parts = signature.trim().replaceAll("\\s+", " ").split(" ");
            this.bytes = new byte[parts.length];
            this.mask = new byte[parts.length];
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].contains("?")) {
                    bytes[i] = 0;
                    mask[i] = 0;
                } else {
                    bytes[i] = (byte) Integer.parseInt(parts[i], 16);
                    mask[i] = (byte) 0xFF;
                }
            }
        }
    }

    public FunctionSignatureGenerator(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    public String generate(Function function) {
        if (function == null || function.isExternal()) {
            return null;
        }

        try {
            Address startAddr = function.getEntryPoint();
            Instruction startInsn = program.getListing().getInstructionContaining(startAddr);
            if (startInsn == null) {
                return null;
            }

            List<Instruction> instructions = getInstructionsFrom(function.getBody(), startInsn.getMinAddress(),
                    MAX_INSTRUCTIONS_TO_SCAN);

            TokenData strictData = tokenizeInstructions(instructions, MaskProfile.STRICT);
            SigResult directResult = findCheapestSignature(strictData);
            if (directResult != null) {
                return directResult.signature;
            }

            SigResult xrefResult = tryXRefSignature(function);
            if (xrefResult != null) {
                return xrefResult.signature;
            }

            TokenData minimalData = tokenizeInstructions(instructions, MaskProfile.MINIMAL);
            SigResult minimalResult = findCheapestSignature(minimalData);
            return minimalResult != null ? minimalResult.signature : null;
        } catch (CancelledException e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private SigResult findCheapestSignature(TokenData data) throws CancelledException {
        List<String> tokens = data.tokens;
        int tokenCount = tokens.size();

        for (int i = 0; i < tokenCount; i++) {
            monitor.checkCancelled();

            if (!data.instructionStartIndices.contains(i)) {
                continue;
            }
            if (i >= MAX_START_OFFSET) {
                break;
            }

            StringBuilder builder = new StringBuilder();
            int byteCount = 0;

            for (int j = i; j < tokenCount; j++) {
                if (builder.length() > 0) {
                    builder.append(" ");
                }
                builder.append(tokens.get(j));
                byteCount++;

                if (byteCount < MIN_WINDOW_BYTES) {
                    continue;
                }
                if (byteCount > MAX_WINDOW_BYTES) {
                    break;
                }

                boolean isInstructionEnd = (j + 1 == tokenCount) || data.instructionStartIndices.contains(j + 1);
                if (!isInstructionEnd) {
                    continue;
                }

                String candidate = builder.toString();
                if (isSignatureUnique(candidate)) {
                    return new SigResult(trimTrailingWildcards(candidate));
                }
            }
        }

        return null;
    }

    private TokenData tokenizeInstructions(List<Instruction> instructions, MaskProfile profile)
            throws MemoryAccessException {
        List<String> allTokens = new ArrayList<>();
        Set<Integer> starts = new HashSet<>();
        int currentOffset = 0;

        for (Instruction instruction : instructions) {
            starts.add(currentOffset);

            byte[] bytes = instruction.getBytes();
            String[] tokens = new String[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                tokens[i] = String.format("%02X", bytes[i]);
            }

            maskRelocations(instruction, tokens);
            maskBranches(instruction, tokens);
            if (profile == MaskProfile.STRICT) {
                maskOperandsSmart(instruction, tokens);
            }

            for (String token : tokens) {
                allTokens.add(token);
            }
            currentOffset += tokens.length;
        }

        return new TokenData(allTokens, starts);
    }

    private void maskRelocations(Instruction instruction, String[] tokens) {
        Address start = instruction.getMinAddress();
        Address end = instruction.getMaxAddress();
        RelocationTable relocationTable = program.getRelocationTable();
        Iterator<Relocation> relocations = relocationTable.getRelocations(new AddressSet(start, end));

        while (relocations.hasNext()) {
            Relocation relocation = relocations.next();
            int offset = (int) relocation.getAddress().subtract(start);
            for (int i = 0; i < 4 && (offset + i) < tokens.length; i++) {
                tokens[offset + i] = "?";
            }
        }
    }

    private void maskBranches(Instruction instruction, String[] tokens) {
        if (!instruction.getFlowType().isCall() && !instruction.getFlowType().isJump()) {
            return;
        }
        if (tokens.length == 0 || tokens[0].contains("?")) {
            return;
        }

        int firstByte = Integer.parseInt(tokens[0], 16);
        if (firstByte == 0xE8 || firstByte == 0xE9) {
            for (int i = 1; i < tokens.length; i++) {
                tokens[i] = "?";
            }
        } else if (tokens.length == 2 && (firstByte == 0xEB || (firstByte & 0xF0) == 0x70)) {
            tokens[1] = "?";
        } else if (tokens.length >= 6 && firstByte == 0x0F && !tokens[1].contains("?")) {
            int secondByte = Integer.parseInt(tokens[1], 16);
            if ((secondByte & 0xF0) == 0x80) {
                for (int i = 2; i < tokens.length; i++) {
                    tokens[i] = "?";
                }
            }
        }
    }

    private void maskOperandsSmart(Instruction instruction, String[] tokens) {
        byte[] bytes;
        try {
            bytes = instruction.getBytes();
        } catch (Exception e) {
            return;
        }

        for (int operandIndex = 0; operandIndex < instruction.getNumOperands(); operandIndex++) {
            boolean shouldMask = false;
            Reference[] refs = instruction.getOperandReferences(operandIndex);

            for (Reference ref : refs) {
                Address toAddress = ref.getToAddress();
                if (toAddress == null) {
                    continue;
                }
                if (toAddress.isExternalAddress()) {
                    shouldMask = true;
                    break;
                }
                MemoryBlock block = program.getMemory().getBlock(toAddress);
                if (block != null && !block.isExecute()) {
                    shouldMask = true;
                    break;
                }
            }

            if (!shouldMask) {
                Object[] operandObjects = instruction.getOpObjects(operandIndex);
                for (Object object : operandObjects) {
                    if (!(object instanceof Scalar)) {
                        continue;
                    }
                    Scalar scalar = (Scalar) object;
                    long value = scalar.getUnsignedValue();
                    if (value <= 0x10000) {
                        continue;
                    }
                    Address possibleAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                    MemoryBlock block = program.getMemory().getBlock(possibleAddress);
                    if (block != null && !block.isExecute()) {
                        shouldMask = true;
                        break;
                    }
                }
            }

            if (!shouldMask) {
                continue;
            }

            for (Reference ref : refs) {
                Address toAddress = ref.getToAddress();
                if (toAddress == null) {
                    continue;
                }
                long target = toAddress.getOffset();
                long instructionEnd = instruction.getAddress().add(bytes.length).getOffset();
                long displacement = target - instructionEnd;
                maskValueInBytes(tokens, bytes, displacement, 4);
            }

            Object[] operandObjects = instruction.getOpObjects(operandIndex);
            for (Object object : operandObjects) {
                if (object instanceof Scalar) {
                    Scalar scalar = (Scalar) object;
                    long value = scalar.getUnsignedValue();
                    maskValueInBytes(tokens, bytes, value, 4);
                    maskValueInBytes(tokens, bytes, value, 8);
                }
            }
        }
    }

    private void maskValueInBytes(String[] tokens, byte[] bytes, long value, int size) {
        if (size > 8 || bytes.length < size) {
            return;
        }

        for (int i = 0; i <= bytes.length - size; i++) {
            long currentValue = 0;
            for (int k = 0; k < size; k++) {
                currentValue |= ((long) (bytes[i + k] & 0xFF)) << (k * 8);
            }

            boolean match = size == 4 ? (int) currentValue == (int) value : currentValue == value;
            if (!match) {
                continue;
            }

            for (int k = 0; k < size; k++) {
                tokens[i + k] = "?";
            }
        }
    }

    private SigResult tryXRefSignature(Function targetFunction) throws Exception {
        Address functionStart = targetFunction.getEntryPoint();
        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(functionStart);

        while (refs.hasNext()) {
            Reference ref = refs.next();
            monitor.checkCancelled();

            if (!ref.getReferenceType().isCall()) {
                continue;
            }

            Address callSite = ref.getFromAddress();
            Function callerFunction = program.getFunctionManager().getFunctionContaining(callSite);
            if (callerFunction == null) {
                continue;
            }

            Instruction instruction = program.getListing().getInstructionAt(callSite);
            if (instruction == null) {
                continue;
            }

            List<Instruction> context = new ArrayList<>();
            context.add(instruction);

            Instruction next = instruction.getNext();
            for (int i = 0; i < XREF_CONTEXT_INSTRUCTIONS && next != null; i++) {
                context.add(next);
                next = next.getNext();
            }

            TokenData data = tokenizeInstructions(context, MaskProfile.STRICT);
            StringBuilder builder = new StringBuilder();
            for (String token : data.tokens) {
                if (builder.length() > 0) {
                    builder.append(" ");
                }
                builder.append(token);
            }

            String fullSignature = builder.toString();
            if (isSignatureUnique(fullSignature)) {
                return new SigResult(trimTrailingWildcards(fullSignature));
            }
        }

        return null;
    }

    private boolean isSignatureUnique(String signature) throws CancelledException {
        try {
            monitor.checkCancelled();
            ByteSignature parsed = new ByteSignature(signature);
            Memory memory = program.getMemory();

            Address firstMatch = memory.findBytes(program.getMinAddress(), parsed.bytes, parsed.mask, true, monitor);
            if (firstMatch == null) {
                return false;
            }

            Address secondSearchStart = firstMatch.next();
            if (secondSearchStart == null) {
                return true;
            }

            Address secondMatch = memory.findBytes(secondSearchStart, program.getMaxAddress(), parsed.bytes,
                    parsed.mask, true, monitor);
            return secondMatch == null;
        } catch (CancelledException e) {
            throw e;
        } catch (Exception e) {
            return false;
        }
    }

    private List<Instruction> getInstructionsFrom(AddressSetView body, Address startAddress, int maxInstructions) {
        List<Instruction> instructions = new ArrayList<>();
        InstructionIterator iterator = program.getListing().getInstructions(startAddress, true);
        int count = 0;

        while (iterator.hasNext() && count < maxInstructions) {
            Instruction instruction = iterator.next();
            if (!body.contains(instruction.getMinAddress())) {
                break;
            }
            instructions.add(instruction);
            count++;
        }

        return instructions;
    }

    private String trimTrailingWildcards(String signature) {
        String[] parts = signature.split(" ");
        int trimCount = 0;
        for (int i = parts.length - 1; i >= 0; i--) {
            if ("?".equals(parts[i])) {
                trimCount++;
            } else {
                break;
            }
        }

        if (trimCount == 0) {
            return signature;
        }

        if (parts.length - trimCount < MIN_WINDOW_BYTES) {
            trimCount = parts.length - MIN_WINDOW_BYTES;
            if (trimCount <= 0) {
                return signature;
            }
        }

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < parts.length - trimCount; i++) {
            if (i > 0) {
                builder.append(" ");
            }
            builder.append(parts[i]);
        }
        return builder.toString();
    }
}
