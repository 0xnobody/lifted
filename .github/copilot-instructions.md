# Lifted - Binary Lifting & Deobfuscation Framework

## Overview
A C++23 binary analysis framework that lifts native binaries to LLVM IR using Remill, applies deobfuscation optimizations, and performs verification with KLEE symbolic execution. The core pipeline: `Binary → Lift → Deobfuscate → Verify`.

**⚠️ RESEARCH PROJECT**: This is an active research prototype with rapid iteration. Code, architecture, and APIs change frequently as features are prototyped, tested, and discarded. Expect temporary/testing code throughout the codebase.

## Architecture

### Major Components
- **Lifters** (`lifter.cpp`, `lifter2.cpp`): Two lifting implementations
  - `lifter.cpp`: **Legacy lifter** - simpler implementation using Remill's `TraceManager`
  - `lifter2.cpp`: **Current lifter** - advanced CFG reconstruction supporting indirect edges (opaque predicates, control flow flattening, switch statements, obfuscated control flow)
  - Both parse binaries via LIEF (ELF/PE/MachO) and lift to LLVM IR via Remill semantics
- **Trace Manager** (`trace-manager.hpp`): Extends `remill::TraceManager` to manage lifted traces, track externals, distinguish defined vs undefined functions
- **Optimization Pipeline** (`opt.hpp/cpp`): Wrapper around LLVM's new PassManager
  - `always_inline()`: Inline all functions (critical for Remill semantic inlining)
  - `default_opt()`: Standard LLVM optimization levels (O1/O2/O3)
  - `run_pass<T>()`: Template for custom passes with full analysis manager setup
- **Custom Passes** (`src/passes/`):
  - `deobfuscation/`: Stack canonicalization, constant memory folding, RAM access normalization
  - `verification/`: Memory intrinsic lowering for KLEE compatibility
  - `analysis/`: Stack alias analysis
  - `redefine_external_calls_pass`: Redirects lifted external calls to user-provided definitions via ABI register extraction
- **Helpers** (`helpers/`): Compiled to LLVM bitcode (`.ll`) and linked into lifted IR
  - `verification-helper.cpp`: KLEE-compatible memory intrinsics (`__remill_read/write_memory_*`)
  - `verification-harness.cpp`: Harness linking `__src_fn` and `__tgt_fn` for equivalence checking
  - `deobfuscation-helper.cpp`: Helper intrinsics for deobfuscation passes
  - `state-utils.cpp`: Register extraction functions (`__extract_rdi`, etc.) for ABI marshaling
- **Slicer** (`slicer.cpp`): Program slicing using MemorySSA and control/data dependency analysis
- **Verification** (`verify.cpp`): KLEE interpreter integration for symbolic execution

### Data Flow (from `main.cpp`)
1. **Lift**: Binary → `lift_function()` → `lifted_ir.ll`
2. **Redefine Externals**: Link `state-utils.ll`, run `RedefineExternalCallsPass` → `lifted_ir_redefined.ll`
3. **Original Verification IR**: Clone + link `verification-helper.ll` + inline → `orig_verif_ir.ll` (produces `__src_fn`)
4. **Deobfuscation**: Link `deobfuscation-helper.ll` + inline + optimize → `deob_ir.ll` (produces `__tgt_fn`)
5. **Verification IR**: Lower memory intrinsics → `deob_verif_ir.ll`
6. **Final Harness**: Link `orig_verif_ir` + `deob_verif_ir` + `verification-harness.ll` → `final_verif_ir.ll`

## Build System

### External Dependencies (via `cmake/Build*.cmake`)
All fetched at configure-time using FetchContent into `external/`:
- **Remill** (LLVM 16): Binary lifting semantics, specific commit `7182636a687e5e005e3336108a653de3aec0362b`
  - **⚠️ CRITICAL**: Project uses LLVM 16. ALL LLVM code must target LLVM 16 APIs only
- **KLEE**: Symbolic execution engine
- **LIEF**: Binary parsing (ELF/PE/MachO)
- **Polaris**: Pattern-based lifting (optional)
- **Souper**: Superoptimizer (optional)
- **z3**, **hiredis**, **klee_expr**, **alive2**: Transitive dependencies

### Build Commands
```bash
# Initial build (slow - fetches all dependencies)
cmake -B build -S .
cmake --build build

# Executable
./build/bin/lifted
```

### Helper Compilation
Helpers are compiled to LLVM bitcode using Clang at build-time (see `helpers/CMakeLists.txt`):
- Uses `-emit-llvm -std=c++17 -O3 -fno-discard-value-names -fstrict-aliasing`
- Outputs to `build/helpers/*.ll` (paths cached in CMake variables like `HELPERS_VERIFICATION_INTRINSICS_PATH`)
- **Critical**: `#define HELPER extern "C" __attribute__((always_inline))` ensures inlining after linking

## Key Conventions

### Namespace Structure
All project code lives in `namespace lifted`:
- `lifted::lifter`: Simple lifter API and result types
- `lifted::opt`: Optimization/pass utilities
- `lifted::helpers`: Helper linking functions
- `lifted::utils`: File I/O, module loading
- `lifted::slicer`: Program slicing
- `lifted::verify`: KLEE integration

### Pass Architecture
Custom passes follow LLVM's New PassManager pattern:
```cpp
struct MyPass : PassInfoMixin<MyPass> {
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
        // Transform logic
        return PreservedAnalyses::none();
    }
};
// Usage: opt::run_pass<MyPass>(function);
```

### Lifter2 Workflow
`Lifter` class (`lifter2.hpp`) uses explicit CFG reconstruction:
1. `Lift(entrypoint)`: Worklist-driven disassembly, builds `Explored` map of basic blocks
2. `LiftedBB`: Tracks RVA range, terminator category, function name
3. `stitchCFG()`: Merges lifted blocks into single function, handles conditional branches
4. `buildPartialCFG()`: Constructs CFG slice from single basic block
5. Constant memory ranges (`ConstMemoryRvaRanges`) enable aggressive folding via `ConstantMemoryFoldingPass`

### Function Naming Patterns
- Lifted blocks: `sub_<rva_hex>` (e.g., `sub_401000`)
- Remill semantics: `__remill_function`, `__remill_basic_block`
- Verification functions: `__src_fn` (original), `__tgt_fn` (deobfuscated)
- ABI helpers: `__extract_<reg>` (e.g., `__extract_rdi`)
- Entry point wrapper: `__unfold_function_systemv_x64_abi`

### Memory Intrinsics
Remill's memory model: `Memory* __remill_write_memory_<N>(Memory*, addr_t, T)` and `T __remill_read_memory_<N>(Memory*, addr_t)`
- For KLEE: Lowered to concrete `rand_memory_state` operations in `verification-helper.cpp`
- For deobfuscation: May be folded to constants if address in `ConstMemoryRvaRanges`

## Common Workflows

### Adding a New Deobfuscation Pass
1. Create `src/passes/deobfuscation/my_pass.{cpp,hpp}`
2. Implement `struct MyPass : PassInfoMixin<MyPass>` with `run(Function&, FAM&)`
3. Add to `src/CMakeLists.txt`
4. Invoke in `main.cpp` after deobfuscation linking: `opt::run_pass<MyPass>(*tgt_fn);`

### Debugging Lifted IR
Intermediate outputs saved to `<binary_dir>/<binary_name>_out/`:
- `lifted_ir.ll`: Raw Remill output
- `deob_linked_ir.ll`: After linking deobfuscation intrinsics + inlining
- `deob_ir.ll`: After optimization passes
- `final_verif_ir.ll`: Final verification harness

### Extending External Function Support
1. Define function signature in a module (see `defs_module` parameter in `lift_function`)
2. Implement in user C++ code, compile to LLVM bitcode
3. `RedefineExternalCallsPass` will rewrite calls at lift sites to extract ABI registers and call your implementation
4. Link `state-utils.ll` for register extraction helpers

## Critical Gotchas

- **LLVM 16 ONLY**: All LLVM code must use LLVM 16 APIs. Verify API compatibility when using advanced features - search the web for "LLVM 16 [feature]" to find correct usage patterns
- **Always inline after linking helpers**: Remill semantics and custom helpers must be inlined to enable optimizations
- **Optimization order matters**: `always_inline()` before `default_opt()`, passes may depend on canonicalized IR
- **Helper compilation uses C++17**: Main codebase is C++23, but helpers target older standard for LLVM bitcode compatibility
- **LIEF format detection**: Use `Binary->format()` switch, then `dynamic_cast` to concrete type (ELF/PE/MachO)
- **RVA vs VA**: LIEF uses virtual addresses, may need to subtract `imagebase()` for PE binaries
- **Lifter2 state**: `Explored`, `Worklist`, `Reprove` sets track CFG discovery - check with `dumpLifterState()` when debugging

## Development Guidelines

- **Rapid prototyping environment**: Code may be temporary, experimental, or destined for replacement
- **LLVM APIs**: When using advanced/obscure LLVM features, search web for LLVM 16-specific documentation and examples
- **Version specificity**: NEVER use LLVM 17+ APIs - they will break compatibility with Remill and dependencies

## Testing & Evaluation
- Evaluation framework in `evaluation/synthetic/` for synthetic test cases
- Many hardcoded paths and constants are for quick prototyping/testing (e.g., `test` export, `/home/atlas/klee-pg/`)
- No formal test suite - validation via manual inspection of lifted IR and KLEE results
- Focus on iterative experimentation rather than production stability
