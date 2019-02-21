//===- BPFAbstractMemberAccess.cpp - Abstracting Member Accesses ---------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This pass abstracted struct/union member accesses like a load of
// "struct base_address + 4" will become "struct base_address + VAR".
// Later on, this VAR will have a reloc record in .BTF.ext containing
// type id of the struct and member, and the member name, enough
// info to reconstruct the member offset right before the bpf prog load.
//===----------------------------------------------------------------------===//

#include "BPF.h"
#include "BPFTargetMachine.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
using namespace llvm;

#define DEBUG_TYPE "bpf-abstruct-member-access"

namespace {
typedef std::set<std::pair<GetElementPtrInst *, std::string>> GEPCandidateSet;

class BPFAbstractMemberAccess final : public ModulePass {
  StringRef getPassName() const override {
    return "BPF Abstract Member Access";
  }

  bool runOnModule(Module &M) override;

public:
  static char ID;
  BPFAbstractMemberAccess() : ModulePass(ID) {}

private:
  bool isBpfProbeReadCall(CallInst *Call);
  bool isBpfProbeReadCandidate(GetElementPtrInst *GEP);
  void computeGEPCandidates(Module &M, GEPCandidateSet &WorkList);
  void transformGEPCandidates(Module &M, GEPCandidateSet &WorkList);
};
} // End anonymous namespace

char BPFAbstractMemberAccess::ID = 0;
INITIALIZE_PASS(BPFAbstractMemberAccess, DEBUG_TYPE,
                "abstracting struct/union member accessees", false, false)

ModulePass *llvm::createBPFAbstractMemberAccess() {
  return new BPFAbstractMemberAccess();
}

bool BPFAbstractMemberAccess::runOnModule(Module &M) {
  LLVM_DEBUG(dbgs() << "********** Abstract Member Accesses **********\n");

  std::set<std::pair<GetElementPtrInst *, std::string>> WorkList;

  computeGEPCandidates(M, WorkList);
  transformGEPCandidates(M, WorkList);

  return !WorkList.empty();
}

bool BPFAbstractMemberAccess::isBpfProbeReadCall(CallInst *Call) {
  const Value *Operand = Call->getCalledValue();

  if (const Constant *CV = dyn_cast<Constant>(Operand)) {
    if (const ConstantExpr *CE = dyn_cast<ConstantExpr>(CV)) {
      for (User::const_op_iterator OI=CE->op_begin(); OI != CE->op_end(); ++OI) {
        if (const ConstantInt *CI2 = dyn_cast<ConstantInt>(*OI)) {
          if (CI2->getValue().getZExtValue() == 4)
            return true;
        }
      }
    }
  }
  return false;
}

bool BPFAbstractMemberAccess::isBpfProbeReadCandidate(GetElementPtrInst *GEP) {
  // we try to catch two following patterns:
  // (1). getelementptr => bitcast => call 4 (bpf_probe_read)
  //  %dev1 = getelementptr inbounds %struct.sk_buff, %struct.sk_buff* %2,
  //          i64 0, i32 0, i32 0, i32 2, i32 0
  //  %4 = bitcast %struct.net_device** %dev1 to i8*
  //  %call = call i32 inttoptr (i64 4 to i32 (i8*, i32, i8*)*)
  //          (i8* nonnull %3, i32 8, i8* nonnull %4) #3
  // (2). getelementptr => call 4 (bpf_probe_read)
  //  %arraydecay6 = getelementptr inbounds %struct.net_device,
  //          %struct.net_device* %5, i64 0, i32 0, i64 0
  //  %call7 = call i32 inttoptr (i64 4 to i32 (i8*, i32, i8*)*)
  //          (i8* nonnull %0, i32 16, i8* %arraydecay6) #3

  for (User *GU : GEP->users()) {
    if (Instruction *Inst = dyn_cast<Instruction>(GU)) {
      if (auto *BI = dyn_cast<BitCastInst>(Inst)) {
        for (User *BU : BI->users()) {
          if (auto *Call = dyn_cast<CallInst>(BU)) {
            if (!isBpfProbeReadCall(Call))
              return false;
          } else {
            return false;
          }
        }
      } else if (auto *Call = dyn_cast<CallInst>(Inst)) {
        if (!isBpfProbeReadCall(Call))
          return false;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }
  return true;
}

void BPFAbstractMemberAccess::computeGEPCandidates(Module &M, GEPCandidateSet &WorkList) {
  for (Function &F : M)
    for (auto &BB : F)
      for (auto &I : BB) {
        if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
          // Find GEP candidates.
          const Type *SrcElemType = GEP->getSourceElementType();
          const auto *CType = dyn_cast<CompositeType>(SrcElemType);
          if (!CType)
            continue;

          // Only handle struct types.
          const auto *SType = dyn_cast<StructType>(CType);
          if (!SType)
            continue;

          // Struct name is needed to pass info to later non-IR based passes.
          if (!SType->hasName())
            continue;

          // The GEP needs to correspond to memory read in kernel.
          if (!isBpfProbeReadCandidate(GEP))
            continue;

          // The number of initial structs and all subsequent member/array indexes
          // must be constant.
          bool ConstantOperands = true;
          std::string IntValues, InitialValue;
          for (unsigned i = 1, E = GEP->getNumOperands(); i != E; ++i) {
            const Value *V = GEP->getOperand(i);
            const auto *IntVal = dyn_cast<ConstantInt>(V);

            if (!IntVal) {
              ConstantOperands = false;
              break;
            }

            if (i == 1)
              InitialValue = IntVal->getValue().toString(10, false);
            else
              IntValues += "." + IntVal->getValue().toString(10, false);
          }
          if (!ConstantOperands)
            continue;

          // Construct the global variable name, which resembers
          // GetElementPtrInst.
          std::string GVName =
              "__BTF_" + InitialValue + "." +
              (SType->getName().substr(7) + StringRef(IntValues)).str() + ".";
          WorkList.insert(std::make_pair(GEP, GVName));
        }
      }
}

void BPFAbstractMemberAccess::transformGEPCandidates(Module &M, GEPCandidateSet &WorkList) {
  for (auto &P : WorkList) {
    auto GEP = P.first;
    auto GVName = P.second;
    BasicBlock *BB = GEP->getParent();

    // For any original GEP like
    //   %dev1 = getelementptr inbounds %struct.sk_buff, %struct.sk_buff* %2,
    //           i64 0, i32 0, i32 0, i32 2, i32 0
    //   %4 = bitcast %struct.net_device** %dev1 to i8*
    // it is transformed to:
    //   %6 = load __BTF_0.sk_buff.0.0.2.0
    //   %7 = bitcast %struct.sk_buff* %6 to i8*
    //   %8 = getelementptr i8, i8* %7, %3
    //   %9 = bitcast i8* %8 to %struct.net_device**
    //   %4 = bitcast %struct.net_device** %9 to i8*
    // The original getelementptr inst is removed.

    // Construct a global variable
    auto *GV =
        new GlobalVariable(M, Type::getInt64Ty(BB->getContext()), false,
                           GlobalVariable::ExternalLinkage, NULL, GVName);
    GV->addAttribute("btf_ama");

    // Load the global variable
    auto *LDInst = new LoadInst(Type::getInt64Ty(BB->getContext()), GV);
    BB->getInstList().insert(GEP->getIterator(), LDInst);

    // Generae a BitCast
    auto *BCInst3 = new BitCastInst(GEP->getPointerOperand(), Type::getInt8PtrTy(BB->getContext()));
    BB->getInstList().insert(GEP->getIterator(), BCInst3);

    // Generate a GetElementPtr
    auto *GEP2 = GetElementPtrInst::Create(Type::getInt8Ty(BB->getContext()),
                                           BCInst3,
                                           LDInst);
    BB->getInstList().insert(GEP->getIterator(), GEP2);

    // Generae a BitCast
    auto *BCInst2 = new BitCastInst(GEP2, GEP->getType());
    BB->getInstList().insert(GEP->getIterator(), BCInst2);

    for (auto UI = GEP->user_begin(), UE = GEP->user_end(); UI != UE;) {
      (*UI)->replaceUsesOfWith(GEP, BCInst2);
      UI++;
    }
    GEP->eraseFromParent();
  }
}
