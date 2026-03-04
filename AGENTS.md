# Lifted - Binary Lifting & Deobfuscation Framework

## Overview
A C++20 (with C++23 features available) binary analysis framework that lifts arbitrary x86-64 binaries to LLVM IR using Remill, applies deobfuscation optimizations, and performs extensible verification via oracle-based cross-execution validation. The core pipeline: `Binary → Lift → Deobfuscate → Verify (JIT + Unicorn + Optional KLEE)`.

**⚠️ RESEARCH PROJECT**: This is an active research prototype with rapid iteration. Code, architecture, and APIs change frequently as features are prototyped, tested, and discarded. Expect temporary/testing code throughout the codebase.

## Architecture

### Major Components
- **Lifter** (`lifter2.hpp/cpp`): Advanced CFG reconstruction engine
  - Worklist-driven disassembly with explicit basic block tracking via `Explored` map
  - Supports indirect edges: opaque predicates, control flow flattening, switch statements, obfuscated control flow
  - Parses binaries via LIEF (ELF/PE/MachO), lifts to LLVM IR via Remill semantics
  - Outputs `Lifted_ir.Module` with basic block stitching via `stitchCFG()`
  - Tracks function names and relative virtual addresses (RVAs) for each block
- **Optimization Pipeline** (`opt.hpp/cpp`): Wrapper around LLVM's new PassManager
  - `always_inline()`: Inline all functions (critical for Remill semantic inlining)
  - `default_opt()`: Standard LLVM optimization levels (O1/O2/O3)
  - `run_pass<T>()`: Template for custom passes with full analysis manager setup
- **Custom Passes** (`src/passes/`):
  - `deobfuscation/`: Stack canonicalization, constant memory folding, RAM direct access normalization
  - `verification/`: Memory intrinsic lowering for KLEE and JIT compatibility
  - `analysis/`: Stack alias analysis
  - `redefine_external_calls_pass`: Redirects lifted external calls to user-provided definitions via ABI register extraction
- **Helpers** (`src/helpers/`): Compiled to LLVM bitcode (`.ll`) and linked into lifted IR
  - `abi-helper.ll`: ABI-related intrinsics for all calling conventions
  - `verification-helper.ll`: Oracle-compatible memory intrinsics for sentinel injection
  - `deobfuscation-helper.ll`: Helper intrinsics for deobfuscation passes
  - `state-utils.ll`: Register extraction functions (`__extract_rdi`, etc.) for ABI marshaling
  - `lifting-helper.ll`: Helpers used during the lifting process
- **Slicer** (`slicer.cpp`): Program slicing using MemorySSA and control/data dependency analysis
- **Verification Framework** (`verification/`):
  - **Executors**: Abstract base class with two implementations:
    - `JITExecutor`: Runs lifted LLVM IR via LLVM ORC JIT for fast execution
    - `UnicornExecutor`: Emulates native binaries via Unicorn to validate lifted code
  - **Memory Management**:
    - `PagedMemoryState`: Manages memory with sentinel value injection for oracle-based testing
    - `SentinelOracle`: Injects values on reads to detect which memory locations are accessed
  - **State Tracking**:
    - `VerifierState`: Tracks register and memory state across execution
    - `StateConversion`: Marshals state between LLVM (JIT) and Unicorn representations
  - **Validation**:
    - `Comparator`: Compares memory/register states between JIT and Unicorn traces
    - `Checkpoint`: Records state snapshots for cross-validation at arbitrary points
  - **Oracle Support**: Sentinel oracle enables testing (detects which memory is read) without functional test cases

### Data Flow (from `main.cpp`)
The verification pipeline runs **two executors in parallel** to validate lifting + deobfuscation:

1. **Lift**: Binary → `Lifter::Lift(rva)` → `Lifted_ir` (LLVM Module + Function)
   - Uses Remill semantics to translate instructions to LLVM IR
   - Tracks all CFG edges in `Lifted_ir::Edges`
   - Maps RVA addresses back to IR constructs

2. **JIT Executor**:
   - Moves lifted module into ORC JIT
   - Runs lifted IR directly with oracle-based memory validation
   - Records checkpoint state at each basic block
   - Detects external function calls and memory accesses

3. **Unicorn Executor** (validates lifting accuracy):
   - Emulates native binary code using Unicorn CPU emulation
   - Runs on original, unmodified binary (ground truth)
   - Shares checkpoint framework with JIT for cross-validation
   - Used to validate that JIT lifted IR matches native execution

4. **Oracle-Based Testing**:
   - `PagedMemoryState` with `SentinelOracle` injects sentinel values on memory reads
   - Detects which memory addresses are actually accessed
   - Eliminates need for functional test cases, works with arbitrary binaries
   - Checkpoints allow cross-validation at arbitrary program points

5. **Comparison** (optional):
   - `Comparator` validates register/memory state equivalence between traces
   - Normalizes for lifter-introduced fallthrough edges
   - Currently disabled in main loop (marked with `/*` block)

## Build System

### External Dependencies (via `cmake/Build*.cmake`)
All fetched at configure-time using FetchContent into `external/`:
- **Remill** (LLVM 16): Binary lifting semantics, specific commit `7182636a687e5e005e3336108a653de3aec0362b`
  - **⚠️ CRITICAL**: Project uses LLVM 16. ALL LLVM code must target LLVM 16 APIs only. Search web for "LLVM 16 [feature]" for API compatibility
- **LLVM 16**: Core IR and JIT infrastructure (ORC JIT)
- **KLEE**: Symbolic execution engine (optional for verification)
- **LIEF**: Binary parsing (ELF/PE/MachO)
- **Unicorn**: CPU emulation engine for native execution validation
- **Polaris**: Pattern-based lifting (optional)
- **Souper**: Superoptimizer (optional)
- **z3**, **hiredis**, **klee_expr**, **alive2**: Transitive dependencies

### Build Commands (via CMake Tools)

**⚠️ ALWAYS use CMake Tools (VSCode) for configuration and building. Never use manual cmake commands for this.**

### Helper Compilation
Helpers are compiled to LLVM bitcode using Clang at build-time (see `src/helpers/CMakeLists.txt`):
- Uses `-emit-llvm -std=c++20 -O3 -fno-discard-value-names -fstrict-aliasing`
- Outputs to `build/helpers/*.ll` (paths cached in CMake variables like `HELPERS_VERIFICATION_INTRINSICS_PATH`)
- **Critical**: Helpers must compile with `-std=c++20` (matching main codebase) for broad LLVM bitcode compatibility
- Note: Helpers use inline declarations (e.g., `extern "C" __attribute__((always_inline))`) to ensure proper inlining after linking

## Key Conventions

### Namespace Structure
All project code lives in `namespace lifted`:
- `lifted::Lifter`: Lifter class and result types (`Lifted_ir`, `Edge`, etc.)
- `lifted::opt`: Optimization/pass utilities
- `lifted::helpers`: Helper linking functions
- `lifted::utils`: File I/O, module loading
- `lifted::slicer`: Program slicing
- `lifted::verification`: Executor framework, memory state, comparator
  - `lifted::verification::Executor`: Abstract base for JIT/Unicorn/symbolic executors
  - `lifted::verification::JITExecutor`: LLVM ORC-based lifted IR execution
  - `lifted::verification::UnicornExecutor`: Native binary emulation
  - `lifted::verification::PagedMemoryState`: Sentinel oracle memory management
- `lifted::abi`: Calling convention abstractions (`CallingConvention`, `SystemVx64CC`)

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

### Lifter Workflow
`Lifter` class (`lifter2.hpp`) uses explicit CFG reconstruction:
1. **`Lift(entrypoint, include_semantics)`**: Worklist-driven disassembly
   - Initializes `Explored` map (RVA → `LiftedBB` metadata)
   - Worklist contains BBs to be lifted
   - Uses Remill to translate each instruction sequence
   - Detects block terminators and their categories (branches, indirect jumps, etc.)
2. **`LiftedBB`**: Metadata for each basic block
   - Type: REAL (known instruction range) or SYNTHETIC (for indirection handling)
   - ID: Unique block identifier
   - RVARange: Instruction address bounds (for REAL blocks)
   - TerminatingCategory: How block exits (conditional branch, indirect jump, etc.)
3. **`stitchCFG()`**: Merges lifted blocks into single function
   - Creates branch instructions for all edges (including synthetic/unresolved ones)
   - Returns `Lifted_ir` with combined module and edge list
4. **CFG Reconstruction Features**:
   - `buildPartialCFG()`: Constructs CFG slice from single basic block
   - Tracks fallthrough edges vs. explicit control flow
   - Supports opaque predicates and switches via symbolic execution detection
5. **Optimization Integration**:
   - Constant memory ranges (`ConstMemoryRvaRanges`) enable aggressive folding via `ConstantMemoryFoldingPass`
   - Stack canonicalization via `CanonicalizeStackPass`
   - Direct memory access normalization via `RAMDirectAccessPass`

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

### Adding a New Feature or Pass

**Always follow this sequence:**
1. Implement the feature in a new header/source pair
2. Integrate into the `lifted` static library in `src/lifter/CMakeLists.txt`
3. **Write tests immediately** using the test framework (see Testing section below)
4. **Build and validate**: `cmake --build build && ./build/bin/lifted_tests`
5. Test integration in `main.cpp` if needed
6. Commit once tests pass

### Adding a New Deobfuscation Pass
1. Create `src/lifter/passes/deobfuscation/my_pass.{cpp,hpp}`
2. Implement `struct MyPass : PassInfoMixin<MyPass>` with `run(Function&, FunctionAnalysisManager&)`
   - Return `PreservedAnalyses::none()` if you modify the function
   - Return `PreservedAnalyses::all()` if you don't modify anything
3. Add sources to `src/lifter/CMakeLists.txt` in the `lifted` target
4. Write unit tests in `src/lifter/tests/test_my_pass.cpp` using the `TEST()` macro
5. Invoke in `main.cpp` or via `opt::run_pass<MyPass>(function);` pattern

### Adding a New Verification Executor
1. Create `src/lifter/verification/my_executor.{hpp,cpp}`
2. Inherit from `lifted::verification::Executor` and implement:
   - `llvm::Error setup_impl() override` - initialize emulator/JIT
   - `llvm::Error run_single_impl(verifier_state&) override` - execute one test case
3. Implement static `create()` factory method
4. Add to `src/lifter/CMakeLists.txt` target
5. Instantiate in `main.cpp` alongside JITExecutor/UnicornExecutor

### Debugging Lifted IR
Intermediate outputs can be saved to files using `utils::output_to_file(path, module.get())`:
- Call at key pipeline points (after lifting, after each pass group, etc.)
- Example: `utils::output_to_file("/home/atlas/lifted/out/lifted.ll", lift_result->Module.get());`
- Examine with `llvm-dis` or text editors

### External Function Integration
1. Define function signatures needed by the binary (e.g., for library imports)
2. Implement in C++ and compile to LLVM bitcode: `-emit-llvm -std=c++20`
3. Link the bitcode module before lifting
4. Use `RedefineExternalCallsPass` to inject ABI wrappers that extract registers and call your implementations
5. Requires `state-utils.ll` for register extraction (`__extract_rdi`, `__extract_rsi`, etc.)

## Critical Gotchas

- **LLVM 16 ONLY**: All LLVM code must use LLVM 16 APIs. Verify API compatibility when using advanced features - search the web for "LLVM 16 [feature]" to find correct usage patterns
- **Always inline after linking helpers**: Remill semantics and custom helpers must be inlined to enable optimizations
- **Optimization order matters**: `always_inline()` before `default_opt()`, passes may depend on canonicalized IR
- **Helper compilation uses C++20**: Main codebase is C++20. Helpers use the same standard for bitcode compatibility
- **LIEF format detection**: Use `Binary->format()` switch, then `dynamic_cast` to concrete type (ELF/PE/MachO)
- **RVA vs VA**: LIEF uses virtual addresses, may need to subtract `imagebase()` for PE binaries
- **Lifter2 state**: `Explored`, `Worklist`, `Reprove` sets track CFG discovery - check with `dumpLifterState()` when debugging

## Development Guidelines

- **Rapid prototyping environment**: Code may be temporary, experimental, or destined for replacement
- **LLVM APIs**: When using advanced/obscure LLVM features, search web for LLVM 16-specific documentation and examples
- **Version specificity**: NEVER use LLVM 17+ APIs - they will break compatibility with Remill and dependencies

## Testing & Evaluation

### Unit Test Framework
- **Custom minimalist framework** in `src/lifter/tests/test_framework.hpp` (zero dependencies)
  - `TEST(name) { ... }` macro registers test cases
  - `CHECK(expr)`, `CHECK_EQ(a,b)`, `CHECK_NE(a,b)`, `CHECK_LT(a,b)`, `CHECK_GT(a,b)` assertions
  - `test::run_all()` executes all registered tests
- **Executable**: `./build/bin/lifted_tests` (built from `src/lifter/tests/test_main.cpp`)
- **Current coverage**:
  - `test_paged_memory.cpp`: PagedMemoryState oracle behavior, sentinel injection, caching
  - `test_sentinel_oracle.cpp`: Sentinel oracle functionality
  - `test_checkpoint.cpp`: Checkpoint recording and comparison

### Synthetic Test Binaries
- Located in `src/evaluation/synthetic/` (15+ test programs):
  - Arithmetic, branching, loops (bounded/unbounded)
  - External function calls with stack arguments
  - Indirect calls, switch statements
  - Local variables, stack operations
- Compiled to shared libraries: `libeval-*.so`
- Lifted/verified via `main.cpp` array `synthetic_test_bins`
- Each has exported `test()` function serving as entry point

### How to Run Tests
```bash
# Build via CMake Tools

# Run unit tests
./build/bin/lifted_tests

# Expected output:
# [ RUN  ] test_name
# [ PASS ] test_name
# ...
# N/M tests passed, K assertions, 0 assertion failures

# Run main executable (lifts all synthetic test binaries)
./build/bin/lifted
# Outputs lifted IR and verification results to logs/stdout
```

### Adding New Tests
1. **Unit tests**: Create `src/lifter/tests/test_my_feature.cpp`
   - Include `test_framework.hpp`
   - Define tests with `TEST(name) { CHECK(...); }`
   - Tests compile into `lifted_tests` executable
2. **Integration tests** (synthetic binaries): Create `src/evaluation/synthetic/my_feature.cpp`
   - Annotate with `POLARIS_ANNOTATE` decorator
   - Export a `test()` function
   - Add to CMakeLists.txt and `synthetic_test_bins` array in main.cpp

### Development Workflow
After implementing a new feature:
1. **Write tests first** (test-driven development recommended)
2. **Build**: `cmake --build build`
3. **Run unit tests**: `./build/bin/lifted_tests` - all must PASS
4. **Verify integration**: `./build/bin/lifted` - check synthetic test results
5. **Only then commit** when all tests are green

### Known Hardcoded Paths & Constants
- `/home/atlas/lifted/out/` - where main.cpp writes lifted IR outputs
- `EVAL_SYNTHETIC_LIBS_DIR` - compiled synthetic test binary directory (set in CMake)
- Many test binaries currently commented out or marked with `//` (work in progress)
- Focus is on iterative experimentation rather than production stability


## lifted-cli

`lifted-cli` is the primary tool for testing and debugging lifting, verification, and deobfuscation behaviour. Use it instead of running `main.cpp` directly whenever you need to isolate a function, a single binary, or a full suite.

**Binary**: `./build/src/lifted-cli/lifted-cli`

### Subcommands

| Subcommand | Purpose | Key flags |
|---|---|---|
| `suite` | Run every function across all targets in a named suite | `--suite <name>`, `--ignore`, `--max-deep-dives` |
| `target` | Run every function in one target binary from a suite | `--suite <name>`, `--target <stem>`, `--ignore`, `--max-deep-dives` |
| `fn` | Run a single function (three modes below) | `--max-deep-dives` |

**`fn` modes** (mutually exclusive):
- **Mode A** — `--binary <path> --rva <hex>`
- **Mode B** — `--binary <path> --export <symbol>`
- **Mode C** — `--suite <name> --target <stem> --func <name>`

**Exit codes**: `0` all pass · `1` at least one divergence · `2` fatal/bad arguments

**Known suites** (baked in at CMake configure time): `synthetic`, `tum-small-programs`, `tum-basic-algorithms`, `tum-simple-hash-functions`

### When to use it

- **Reproducing a lifting bug**: use `fn` Mode B or A to pin down the exact function and inspect `[LIFTING]` / `[RESULT]` output.
- **Verifying a pass or pipeline change**: run `suite --suite synthetic --max-deep-dives 0` before and after the patch; the summary line shows regressions immediately.
- **Running a tight loop over one binary**: use `target` to avoid waiting for the whole suite.
- **Deep-dive analysis**: leave `--max-deep-dives` at its default of 1 to get the first diverging test-case detail printed inline.

### Where to modify pipeline behaviour

All shared lifting + verification logic lives in `src/eval-suite/`:

- **`eval_pipeline.cpp`** — `lift_and_verify_named()` and the two-stage default pipeline (SeedSweepStage wide ×50 + loop-breaker ×100). Edit here to change pass ordering, stage parameters, or add new pipeline stages.
- **`eval_pipeline.hpp`** — `LiftAndVerifyResult` struct and public API. Extend if you need new output fields (e.g. a second deep-dive, per-stage stats).
- **`eval_utils.hpp/cpp`** — `rva_from_export`, `get_section_bounds`. Add binary-introspection helpers here.
- **`suite.hpp/cpp`** — `parse_suite_csv`, `parse_targets_csv`. Touch only if the CSV format changes.