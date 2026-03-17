#pragma once
#include "ir_mutation.hpp"
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstrTypes.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace lifted::fault_injection {

// ---------------------------------------------------------------------------
// Abstract interface
// ---------------------------------------------------------------------------

struct IRMutator {
    virtual bool can_mutate(llvm::Instruction *instr) const = 0;
    // Apply the mutation. Returns the live Value* representing the result:
    // the replacement instruction (erasing operators), the modified instruction
    // (in-place operators), or the replacement operand (InstrDropper).
    // Caller must not use the original instruction pointer after this call if
    // the operator erases it.
    virtual llvm::Value *mutate(llvm::Instruction *instr) const = 0;
    virtual std::string_view name() const = 0;
    virtual ~IRMutator() = default;
};

// ---------------------------------------------------------------------------
// Base classes — implemented in mutation_operators.cpp
// ---------------------------------------------------------------------------

// Replaces a BinaryOperator opcode with a different one.
// Emits a new instruction, redirects uses, erases original.
struct BinaryOpcodeReplacer : IRMutator {
    llvm::Instruction::BinaryOps from_op;
    llvm::Instruction::BinaryOps to_op;
    std::string_view op_name;

    BinaryOpcodeReplacer(llvm::Instruction::BinaryOps f,
                         llvm::Instruction::BinaryOps t,
                         std::string_view n)
        : from_op(f), to_op(t), op_name(n) {}

    bool can_mutate(llvm::Instruction *I) const override;
    llvm::Value *mutate(llvm::Instruction *I) const override;
    std::string_view name() const override { return op_name; }
};

// Replaces an ICmp predicate with a different one.
// Emits a new ICmpInst, redirects uses, erases original.
struct ICmpPredicateReplacer : IRMutator {
    llvm::CmpInst::Predicate from_pred;
    llvm::CmpInst::Predicate to_pred;
    std::string_view pred_name;

    ICmpPredicateReplacer(llvm::CmpInst::Predicate f,
                          llvm::CmpInst::Predicate t,
                          std::string_view n)
        : from_pred(f), to_pred(t), pred_name(n) {}

    bool can_mutate(llvm::Instruction *I) const override;
    llvm::Value *mutate(llvm::Instruction *I) const override;
    std::string_view name() const override { return pred_name; }
};

// Swaps operands 0 and 1 of a non-commutative BinaryOperator in place.
struct OperandSwapper : IRMutator {
    llvm::Instruction::BinaryOps op;
    std::string_view swap_name;

    OperandSwapper(llvm::Instruction::BinaryOps o, std::string_view n)
        : op(o), swap_name(n) {}

    bool can_mutate(llvm::Instruction *I) const override;
    llvm::Value *mutate(llvm::Instruction *I) const override;
    std::string_view name() const override { return swap_name; }
};

// Replaces the result of an instruction with one of its operands (RAUW only;
// the instruction is left dead for DCE).
struct InstrDropper : IRMutator {
    unsigned opcode;
    unsigned operand_idx;
    std::string_view drop_name;

    InstrDropper(unsigned opc, unsigned idx, std::string_view n)
        : opcode(opc), operand_idx(idx), drop_name(n) {}

    bool can_mutate(llvm::Instruction *I) const override;
    llvm::Value *mutate(llvm::Instruction *I) const override;
    std::string_view name() const override { return drop_name; }
};

// Replaces a ConstantInt operand with 42 (if it was 0) or 0 (otherwise).
struct ConstIntReplacer : IRMutator {
    unsigned operand_idx;
    int64_t replacement_val; // used when original is zero
    std::string_view repl_name;

    ConstIntReplacer(unsigned idx, int64_t val, std::string_view n)
        : operand_idx(idx), replacement_val(val), repl_name(n) {}

    bool can_mutate(llvm::Instruction *I) const override;
    llvm::Value *mutate(llvm::Instruction *I) const override;
    std::string_view name() const override { return repl_name; }
};

// Negates a trunc-to-i1: inserts `xor trunc, true` and redirects uses.
struct NegateTrunc : IRMutator {
    bool can_mutate(llvm::Instruction *I) const override;
    llvm::Value *mutate(llvm::Instruction *I) const override;
    std::string_view name() const override { return "NegateTruncReplacement"; }
};

// Mutates `xor a, b` → `xor a, (not b)` by inserting a NOT before the XOR.
struct NegateXOR : IRMutator {
    bool can_mutate(llvm::Instruction *I) const override;
    llvm::Value *mutate(llvm::Instruction *I) const override;
    std::string_view name() const override { return "NegateXORReplacement"; }
};

// ---------------------------------------------------------------------------
// Concrete subclass generators
// ---------------------------------------------------------------------------

// ARITHMETIC — BinaryOp opcode swap
#define BINOP_REPL(Cls, From, To)                                              \
    struct Cls : BinaryOpcodeReplacer {                                        \
        Cls() : BinaryOpcodeReplacer(llvm::Instruction::From,                  \
                                     llvm::Instruction::To, #Cls) {}           \
    }

BINOP_REPL(AddToSub,    Add,  Sub);
BINOP_REPL(SubToAdd,    Sub,  Add);
BINOP_REPL(MulToSDiv,   Mul,  SDiv);
BINOP_REPL(MulToUDiv,   Mul,  UDiv);
BINOP_REPL(SDivToMul,   SDiv, Mul);
BINOP_REPL(UDivToMul,   UDiv, Mul);
BINOP_REPL(SDivToSRem,  SDiv, SRem);
BINOP_REPL(SRemToSDiv,  SRem, SDiv);
BINOP_REPL(UDivToURem,  UDiv, URem);
BINOP_REPL(URemToUDiv,  URem, UDiv);

// BITWISE — BinaryOp opcode swap
BINOP_REPL(AndToOr,     And,  Or);
BINOP_REPL(OrToAnd,     Or,   And);
BINOP_REPL(XorToOr,     Xor,  Or);
BINOP_REPL(XorToAnd,    Xor,  And);
BINOP_REPL(ShlToLShr,   Shl,  LShr);
BINOP_REPL(LShrToShl,   LShr, Shl);
BINOP_REPL(AShrToShl,   AShr, Shl);

#undef BINOP_REPL

// COMPARISON_NEG — negate predicate (logical complement)
#define ICMP_REPL(Cls, From, To)                                               \
    struct Cls : ICmpPredicateReplacer {                                        \
        Cls() : ICmpPredicateReplacer(llvm::CmpInst::From,                     \
                                      llvm::CmpInst::To, #Cls) {}              \
    }

ICMP_REPL(ICMP_EQToICMP_NE,   ICMP_EQ,  ICMP_NE);
ICMP_REPL(ICMP_NEToICMP_EQ,   ICMP_NE,  ICMP_EQ);
ICMP_REPL(ICMP_SGTToICMP_SLE, ICMP_SGT, ICMP_SLE);
ICMP_REPL(ICMP_SLEToICMP_SGT, ICMP_SLE, ICMP_SGT);
ICMP_REPL(ICMP_SGEToICMP_SLT, ICMP_SGE, ICMP_SLT);
ICMP_REPL(ICMP_SLTToICMP_SGE, ICMP_SLT, ICMP_SGE);
ICMP_REPL(ICMP_UGTToICMP_ULE, ICMP_UGT, ICMP_ULE);
ICMP_REPL(ICMP_ULEToICMP_UGT, ICMP_ULE, ICMP_UGT);
ICMP_REPL(ICMP_UGEToICMP_ULT, ICMP_UGE, ICMP_ULT);
ICMP_REPL(ICMP_ULTToICMP_UGE, ICMP_ULT, ICMP_UGE);

// COMPARISON_BDRY — off-by-one predicate shift
ICMP_REPL(ICMP_SGTToICMP_SGE, ICMP_SGT, ICMP_SGE);
ICMP_REPL(ICMP_SGEToICMP_SGT, ICMP_SGE, ICMP_SGT);
ICMP_REPL(ICMP_SLTToICMP_SLE, ICMP_SLT, ICMP_SLE);
ICMP_REPL(ICMP_SLEToICMP_SLT, ICMP_SLE, ICMP_SLT);
ICMP_REPL(ICMP_UGTToICMP_UGE, ICMP_UGT, ICMP_UGE);
ICMP_REPL(ICMP_UGEToICMP_UGT, ICMP_UGE, ICMP_UGT);
ICMP_REPL(ICMP_ULTToICMP_ULE, ICMP_ULT, ICMP_ULE);
ICMP_REPL(ICMP_ULEToICMP_ULT, ICMP_ULE, ICMP_ULT);

#undef ICMP_REPL

// OPERAND_SWAP — swap lhs/rhs of non-commutative ops
#define OP_SWAP(Cls, Op)                                                       \
    struct Cls : OperandSwapper {                                               \
        Cls() : OperandSwapper(llvm::Instruction::Op, #Cls) {}                 \
    }

OP_SWAP(SwapSubOperands,  Sub);
OP_SWAP(SwapSDivOperands, SDiv);
OP_SWAP(SwapUDivOperands, UDiv);
OP_SWAP(SwapSRemOperands, SRem);
OP_SWAP(SwapURemOperands, URem);
OP_SWAP(SwapShlOperands,  Shl);
OP_SWAP(SwapLShrOperands, LShr);
OP_SWAP(SwapAShrOperands, AShr);

#undef OP_SWAP

// DROP_COMPUTATION — replace result with one of the instruction's operands
#define INSTR_DROP(Cls, Op, Idx)                                               \
    struct Cls : InstrDropper {                                                 \
        Cls() : InstrDropper(llvm::Instruction::Op, Idx, #Cls) {}              \
    }

INSTR_DROP(SwapAddWithOperand_0, Add, 0);
INSTR_DROP(SwapAddWithOperand_1, Add, 1);
INSTR_DROP(SwapSubWithOperand_0, Sub, 0);
INSTR_DROP(SwapSubWithOperand_1, Sub, 1);
INSTR_DROP(SwapMulWithOperand_0, Mul, 0);
INSTR_DROP(SwapMulWithOperand_1, Mul, 1);

#undef INSTR_DROP

// CONSTANT_REPL — replace a ConstantInt operand with 42 or 0
struct ConstIntReplacement_Op0_42 : ConstIntReplacer {
    ConstIntReplacement_Op0_42() : ConstIntReplacer(0, 42, "ConstIntReplacement_Op0_42") {}
};
struct ConstIntReplacement_Op1_42 : ConstIntReplacer {
    ConstIntReplacement_Op1_42() : ConstIntReplacer(1, 42, "ConstIntReplacement_Op1_42") {}
};

// ---------------------------------------------------------------------------
// Owned table entry
// ---------------------------------------------------------------------------

struct CategorizedMutation {
    std::unique_ptr<IRMutator> op; // owned
    MutationCategory category;
    std::string name; // human-readable, e.g. "AddToSub"

    difficulty_t difficulty() const { return static_difficulty(category); }
};

// Returns all integer-relevant operators. The returned vector is owned by a
// static inside this function; pointer stability is guaranteed for the
// process lifetime.
const std::vector<CategorizedMutation> &all_integer_operators();

} // namespace lifted::fault_injection
