#include "mutation_operators.hpp"
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>

namespace lifted::fault_injection {

// ---------------------------------------------------------------------------
// BinaryOpcodeReplacer
// ---------------------------------------------------------------------------

bool BinaryOpcodeReplacer::can_mutate(llvm::Instruction *I) const {
    // Only match the specific opcode on integer types; float arithmetic uses
    // the same opcodes but different semantics — do not perturb those.
    return I->getOpcode() == static_cast<unsigned>(from_op) &&
           I->getType()->isIntegerTy();
}

llvm::Value *BinaryOpcodeReplacer::mutate(llvm::Instruction *I) const {
    auto *lhs  = I->getOperand(0);
    auto *rhs  = I->getOperand(1);
    auto name  = I->getName().str(); // preserve SSA name for readable after-string
    auto *repl = llvm::BinaryOperator::Create(to_op, lhs, rhs, "");
    repl->insertAfter(I);
    I->replaceAllUsesWith(repl);
    I->eraseFromParent();
    repl->setName(name); // claim original name now that I is gone
    return repl;
}

// ---------------------------------------------------------------------------
// ICmpPredicateReplacer
// ---------------------------------------------------------------------------

bool ICmpPredicateReplacer::can_mutate(llvm::Instruction *I) const {
    auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(I);
    return cmp && cmp->getPredicate() == from_pred;
}

llvm::Value *ICmpPredicateReplacer::mutate(llvm::Instruction *I) const {
    auto *cmp  = llvm::cast<llvm::ICmpInst>(I);
    auto *lhs  = cmp->getOperand(0);
    auto *rhs  = cmp->getOperand(1);
    auto name  = cmp->getName().str();
    // CmpInst::Create(op, pred, lhs, rhs, name, InsertBefore) — LLVM 16 API.
    auto *repl = llvm::CmpInst::Create(llvm::Instruction::ICmp, to_pred,
                                       lhs, rhs, "");
    repl->insertAfter(cmp);
    cmp->replaceAllUsesWith(repl);
    cmp->eraseFromParent();
    repl->setName(name);
    return repl;
}
// ---------------------------------------------------------------------------
// OperandSwapper
// ---------------------------------------------------------------------------

bool OperandSwapper::can_mutate(llvm::Instruction *I) const {
    return I->getOpcode() == static_cast<unsigned>(op) &&
           I->getType()->isIntegerTy();
}

llvm::Value *OperandSwapper::mutate(llvm::Instruction *I) const {
    auto *lhs = I->getOperand(0);
    I->setOperand(0, I->getOperand(1));
    I->setOperand(1, lhs);
    return I;
}

// ---------------------------------------------------------------------------
// InstrDropper
// ---------------------------------------------------------------------------

bool InstrDropper::can_mutate(llvm::Instruction *I) const {
    return I->getOpcode() == opcode &&
           I->getType()->isIntegerTy() &&
           operand_idx < I->getNumOperands();
}

llvm::Value *InstrDropper::mutate(llvm::Instruction *I) const {
    // Save the replacement operand before RAUW (RAUW doesn't touch operands).
    llvm::Value *replacement = I->getOperand(operand_idx);
    // RAUW with one operand; the original instruction is left dead for DCE.
    // We intentionally do NOT erase: structurally harmless as a def with no uses.
    I->replaceAllUsesWith(replacement);
    return replacement;
}

// ---------------------------------------------------------------------------
// ConstIntReplacer
// ---------------------------------------------------------------------------

bool ConstIntReplacer::can_mutate(llvm::Instruction *I) const {
    if (I->getNumOperands() <= operand_idx) return false;
    // AllocaInst size operands look like ConstantInts but mutating them
    // invalidates stack layout in ways that confuse the executor.
    if (llvm::isa<llvm::AllocaInst>(I)) return false;
    // CallInst arguments may be lifetime intrinsic size args or other
    // infrastructure constants.  Skip calls entirely.
    if (llvm::isa<llvm::CallInst>(I)) return false;
    // StoreInst value operand (0) = Remill flag-clear stores; skip.
    if (llvm::isa<llvm::StoreInst>(I)) return false;
    // Never replace a non-zero divisor with 0 — that causes SIGFPE in JIT.
    // Divisor is always operand 1 for sdiv/udiv/srem/urem.
    if (operand_idx == 1) {
        unsigned opc = I->getOpcode();
        if (opc == llvm::Instruction::SDiv || opc == llvm::Instruction::UDiv ||
            opc == llvm::Instruction::SRem || opc == llvm::Instruction::URem) {
            auto *c = llvm::dyn_cast<llvm::ConstantInt>(I->getOperand(operand_idx));
            // If constant is non-zero, we'd replace with 0 → SIGFPE.
            if (c && !c->isZero()) return false;
        }
    }
    return llvm::isa<llvm::ConstantInt>(I->getOperand(operand_idx));
}

llvm::Value *ConstIntReplacer::mutate(llvm::Instruction *I) const {
    auto *c = llvm::cast<llvm::ConstantInt>(I->getOperand(operand_idx));
    llvm::Value *repl;
    if (c->isZero()) {
        // Replace zero with the non-trivial replacement value.
        repl = llvm::ConstantInt::get(
            c->getType(),
            llvm::APInt(c->getType()->getIntegerBitWidth(),
                        static_cast<uint64_t>(replacement_val), /*isSigned=*/true));
    } else {
        // Collapse anything non-zero to zero.
        repl = llvm::ConstantInt::get(c->getType(), 0);
    }
    I->setOperand(operand_idx, repl);
    return I;
}

// ---------------------------------------------------------------------------
// NegateTrunc
// ---------------------------------------------------------------------------

bool NegateTrunc::can_mutate(llvm::Instruction *I) const {
    auto *t = llvm::dyn_cast<llvm::TruncInst>(I);
    return t && t->getDestTy()->getIntegerBitWidth() == 1;
}

llvm::Value *NegateTrunc::mutate(llvm::Instruction *I) const {
    // Build: notI = xor I, true
    // Then redirect all original uses of I to notI.
    //
    // Subtlety: replaceAllUsesWith also patches notI's own operand (which uses
    // I), turning notI into "xor notI, true" (circular). We fix that back with
    // replaceUsesOfWith.
    auto *notI = llvm::BinaryOperator::CreateNot(I, "not");
    notI->insertAfter(I);
    I->replaceAllUsesWith(notI);
    // Restore notI's operand 0, which was clobbered by the RAUW above.
    notI->replaceUsesOfWith(notI, I);
    return notI;
}

// ---------------------------------------------------------------------------
// NegateXOR
// ---------------------------------------------------------------------------

bool NegateXOR::can_mutate(llvm::Instruction *I) const {
    return I->getOpcode() == llvm::Instruction::Xor &&
           I->getType()->isIntegerTy();
}

llvm::Value *NegateXOR::mutate(llvm::Instruction *I) const {
    // Insert NOT of rhs immediately before the XOR, then set XOR's rhs to it.
    // CreateNot(V, Name, InsertBefore) inserts before InsertBefore — LLVM 16.
    auto *rhs    = I->getOperand(1);
    auto *notRhs = llvm::BinaryOperator::CreateNot(rhs, "not", I);
    I->setOperand(1, notRhs);
    return I;
}

// ---------------------------------------------------------------------------
// all_integer_operators()
// ---------------------------------------------------------------------------

const std::vector<CategorizedMutation> &all_integer_operators() {
    using Cat = MutationCategory;

    static std::vector<CategorizedMutation> table = []() {
        std::vector<CategorizedMutation> v;
        v.reserve(53);

        auto add = [&](Cat cat, std::string nm, auto mutator) {
            using T = std::decay_t<decltype(mutator)>;
            v.push_back(CategorizedMutation{
                std::make_unique<T>(std::move(mutator)),
                cat,
                std::move(nm),
            });
        };

        // ── ARITHMETIC ──────────────────────────────────────────────────────
        // NOTE: MulToSDiv and MulToUDiv are intentionally omitted.
        // They introduce sdiv/udiv on mul operands that may legally be 0,
        // causing SIGFPE in the JIT (un-catchable in-process).
        // SDivToMul/UDivToMul are safe: existing divisors are already non-zero.
        // SDiv↔SRem/UDiv↔URem preserve the divisor so cannot introduce new SIGFPE.
        add(Cat::ARITHMETIC, "AddToSub",    AddToSub{});
        add(Cat::ARITHMETIC, "SubToAdd",    SubToAdd{});
        add(Cat::ARITHMETIC, "SDivToMul",   SDivToMul{});
        add(Cat::ARITHMETIC, "UDivToMul",   UDivToMul{});
        add(Cat::ARITHMETIC, "SDivToSRem",  SDivToSRem{});
        add(Cat::ARITHMETIC, "SRemToSDiv",  SRemToSDiv{});
        add(Cat::ARITHMETIC, "UDivToURem",  UDivToURem{});
        add(Cat::ARITHMETIC, "URemToUDiv",  URemToUDiv{});
        // ── BITWISE ─────────────────────────────────────────────────────────
        add(Cat::BITWISE, "AndToOr",              AndToOr{});
        add(Cat::BITWISE, "OrToAnd",              OrToAnd{});
        add(Cat::BITWISE, "XorToOr",              XorToOr{});
        add(Cat::BITWISE, "XorToAnd",             XorToAnd{});
        add(Cat::BITWISE, "ShlToLShr",            ShlToLShr{});
        add(Cat::BITWISE, "LShrToShl",            LShrToShl{});
        add(Cat::BITWISE, "AShrToShl",            AShrToShl{});
        add(Cat::BITWISE, "NegateXORReplacement", NegateXOR{});

        // ── COMPARISON_NEG ──────────────────────────────────────────────────
        add(Cat::COMPARISON_NEG, "ICMP_EQToICMP_NE",   ICMP_EQToICMP_NE{});
        add(Cat::COMPARISON_NEG, "ICMP_NEToICMP_EQ",   ICMP_NEToICMP_EQ{});
        add(Cat::COMPARISON_NEG, "ICMP_SGTToICMP_SLE", ICMP_SGTToICMP_SLE{});
        add(Cat::COMPARISON_NEG, "ICMP_SLEToICMP_SGT", ICMP_SLEToICMP_SGT{});
        add(Cat::COMPARISON_NEG, "ICMP_SGEToICMP_SLT", ICMP_SGEToICMP_SLT{});
        add(Cat::COMPARISON_NEG, "ICMP_SLTToICMP_SGE", ICMP_SLTToICMP_SGE{});
        add(Cat::COMPARISON_NEG, "ICMP_UGTToICMP_ULE", ICMP_UGTToICMP_ULE{});
        add(Cat::COMPARISON_NEG, "ICMP_ULEToICMP_UGT", ICMP_ULEToICMP_UGT{});
        add(Cat::COMPARISON_NEG, "ICMP_UGEToICMP_ULT", ICMP_UGEToICMP_ULT{});
        add(Cat::COMPARISON_NEG, "ICMP_ULTToICMP_UGE", ICMP_ULTToICMP_UGE{});

        // ── COMPARISON_BDRY ─────────────────────────────────────────────────
        add(Cat::COMPARISON_BDRY, "ICMP_SGTToICMP_SGE", ICMP_SGTToICMP_SGE{});
        add(Cat::COMPARISON_BDRY, "ICMP_SGEToICMP_SGT", ICMP_SGEToICMP_SGT{});
        add(Cat::COMPARISON_BDRY, "ICMP_SLTToICMP_SLE", ICMP_SLTToICMP_SLE{});
        add(Cat::COMPARISON_BDRY, "ICMP_SLEToICMP_SLT", ICMP_SLEToICMP_SLT{});
        add(Cat::COMPARISON_BDRY, "ICMP_UGTToICMP_UGE", ICMP_UGTToICMP_UGE{});
        add(Cat::COMPARISON_BDRY, "ICMP_UGEToICMP_UGT", ICMP_UGEToICMP_UGT{});
        add(Cat::COMPARISON_BDRY, "ICMP_ULTToICMP_ULE", ICMP_ULTToICMP_ULE{});
        add(Cat::COMPARISON_BDRY, "ICMP_ULEToICMP_ULT", ICMP_ULEToICMP_ULT{});

        // ── OPERAND_SWAP ────────────────────────────────────────────────────
        add(Cat::OPERAND_SWAP, "SwapSubOperands",  SwapSubOperands{});
        // NOTE: SwapSDiv/UDiv/SRem/URemOperands omitted: puts the numerator
        // (may be 0) as divisor, causing SIGFPE in JIT.
        add(Cat::OPERAND_SWAP, "SwapShlOperands",  SwapShlOperands{});
        add(Cat::OPERAND_SWAP, "SwapLShrOperands", SwapLShrOperands{});
        add(Cat::OPERAND_SWAP, "SwapAShrOperands", SwapAShrOperands{});

        // ── DROP_COMPUTATION ─────────────────────────────────────────────────
        add(Cat::DROP_COMPUTATION, "SwapAddWithOperand_0", SwapAddWithOperand_0{});
        add(Cat::DROP_COMPUTATION, "SwapAddWithOperand_1", SwapAddWithOperand_1{});
        add(Cat::DROP_COMPUTATION, "SwapSubWithOperand_0", SwapSubWithOperand_0{});
        add(Cat::DROP_COMPUTATION, "SwapSubWithOperand_1", SwapSubWithOperand_1{});
        add(Cat::DROP_COMPUTATION, "SwapMulWithOperand_0", SwapMulWithOperand_0{});
        add(Cat::DROP_COMPUTATION, "SwapMulWithOperand_1", SwapMulWithOperand_1{});

        // ── CONSTANT_REPL ────────────────────────────────────────────────────
        // ConstIntReplacement_Op0_42: replaces constant numerator (operand 0).
        // SAFE: numerator of 0 just yields 0; no SIGFPE risk.
        add(Cat::CONSTANT_REPL, "ConstIntReplacement_Op0_42", ConstIntReplacement_Op0_42{});
        // ConstIntReplacement_Op1_42 (operand 1 = potential divisor position) is
        // intentionally omitted from the default set.  Even with the non-zero-divisor
        // guard in can_mutate(), inlined Remill semantics contain sdiv/srem instructions
        // that may receive sentinel-randomised inputs driving the divisor to 0, causing
        // an un-catchable SIGFPE in the JIT.  Op1 replacement can be enabled explicitly
        // via --categories constant_repl if the target is known to be div-free.

        // ── NEGATE_TRUNC ─────────────────────────────────────────────────────
        add(Cat::NEGATE_TRUNC, "NegateTruncReplacement", NegateTrunc{});

        return v;
    }();

    return table;
}

} // namespace lifted::fault_injection
