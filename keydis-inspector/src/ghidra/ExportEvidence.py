# Evidence-only headless decompilation. Executable is imported, never executed.
# @category DFIR
from ghidra.app.decompiler import DecompInterface
import json
import sys

def main():
    args = getScriptArgs()
    if len(args) < 2:
        raise ValueError("Expected output.json and max_functions")
    out_path = args[0]
    max_functions = max(1, min(500, int(args[1])))
    interface = DecompInterface()
    if not interface.openProgram(currentProgram):
        raise RuntimeError("Ghidra decompiler could not open program")
    rows = []
    errors = []
    count = 0
    iterator = currentProgram.getFunctionManager().getFunctions(True)
    while iterator.hasNext():
        if monitor.isCancelled():
            break
        func = iterator.next()
        if func.isExternal():
            continue
        if count >= max_functions:
            break
        count += 1
        name = str(func.getName())
        addr = str(func.getEntryPoint())
        entry = int(func.getEntryPoint().getOffset())
        row = {"name":name, "entry_address":addr, "entry_va":entry,
               "is_thunk":bool(func.isThunk()), "decompilation_status":"unavailable",
               "pseudocode":None, "function_signature":str(func.getSignature())}
        try:
            dec = interface.decompileFunction(func, 15, monitor)
            if dec is not None and dec.decompileCompleted():
                output = dec.getDecompiledFunction()
                if output is not None:
                    content = str(output.getC())
                    row["pseudocode"] = content[:60000]
                    row["decompilation_status"] = "completed"
                    if len(content) > 60000:
                        row["truncated"] = True
            else:
                errors.append({"function":addr, "error":"decompilation unavailable"})
        except Exception as e:
            errors.append({"function":addr, "error":str(e)})
        rows.append(row)
    interface.dispose()
    result = {"schema_version":1, "program_name":str(currentProgram.getName()),
              "architecture":str(currentProgram.getLanguageID()), "image_base":str(currentProgram.getImageBase()),
              "functions":rows, "functions_processed":len(rows), "max_functions":max_functions,
              "errors":errors[:50],
              "caution":"Pseudocode is reconstructed and not ground truth; cross-check with instructions, references and runtime context."}
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=True)
    print("DFIR deep evidence written to " + out_path)

main()
