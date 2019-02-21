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
// type id of the struct and traversal strings, enough
// info to reconstruct the member offset right before the bpf prog load.
//===----------------------------------------------------------------------===//

#include "BPF.h"
#include "BPFTargetMachine.h"
#include "llvm/IR/DebugInfoMetadata.h"
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
typedef std::map<GetElementPtrInst *, std::string> GEPCandidateSet;

class BPFAbstractMemberAccess final : public ModulePass {
  StringRef getPassName() const override {
    return "BPF Abstract Member Access";
  }

  bool runOnModule(Module &M) override;

public:
  static char ID;
  BPFAbstractMemberAccess() : ModulePass(ID), TM(nullptr) {}
  BPFAbstractMemberAccess(BPFTargetMachine *TM) : ModulePass(ID), TM(TM) {}

private:
  BPFTargetMachine *TM;

  std::map<std::string, const DICompositeType *> StructDITypes;
  std::map<std::string, const DIDerivedType *> TypedefDITypes;
  std::map<std::string, GlobalVariable *> GEPGlobals;
  std::map<GetElementPtrInst *, GetElementPtrInst *> GEPDependInsts;
  std::map<std::string, std::pair<const DICompositeType *, std::string>> STypeToDIStruct;
  std::set<const DIType *> VisitedDITypes;

  void collectDITypes(Module &M, Function &F);
  void visitDIType(const DIType *Ty);
  const DICompositeType *getDIStruct(std::string StructName);

  void collectGEPs(Function &F, std::map<GetElementPtrInst *, std::set<CallInst *>> &TmpBpfProbeCalls);
  void processGEPs(GEPCandidateSet &WorkList, std::map<GetElementPtrInst *, std::set<CallInst *>> &TmpBpfProbeCalls);
  void processGEP(GetElementPtrInst *GEP, GEPCandidateSet &WorkList,
                  std::map<GetElementPtrInst *, std::set<CallInst *>> &TmpBpfProbeCalls,
                  std::set<GetElementPtrInst *> &VisitedGEPs);

  const DIType *stripQualifiers(const DIType *Ty);
  bool isBpfProbeReadCall(CallInst *Call);
  uint32_t computeDIMemberIndex(const DICompositeType *DIStruct, const StructType *SType, uint32_t STIndex);
  bool checkAndAddGEP(GetElementPtrInst *GEP, GEPCandidateSet &WorkList);
  bool computeMemberAccessString(GetElementPtrInst *GEP, const StructType *SType,
                                 const DICompositeType *DIStruct, std::string &GVName,
                                 std::string &Prefix, std::vector<unsigned> &ArrayBounds);
  void computeGEPCandidates(Module &M, GEPCandidateSet &WorkList, std::set<CallInst *> &BpfProbeCalls);
  void checkBpfProbeCalls(Module &M, std::set<CallInst *> &BpfProbeCalls);
  void transformGEPCandidates(Module &M, GEPCandidateSet &WorkList);
};
} // End anonymous namespace

char BPFAbstractMemberAccess::ID = 0;
INITIALIZE_PASS(BPFAbstractMemberAccess, DEBUG_TYPE,
                "abstracting struct/union member accessees", false, false)

ModulePass *llvm::createBPFAbstractMemberAccess(BPFTargetMachine *TM) {
  return new BPFAbstractMemberAccess(TM);
}

bool BPFAbstractMemberAccess::runOnModule(Module &M) {
  LLVM_DEBUG(dbgs() << "********** Abstract Member Accesses **********\n");

  const BPFSubtarget *SubTarget = TM->getSubtargetImpl();
  if (!SubTarget->getHasOffsetReloc())
    return false;

  unsigned NumDebugCUs = std::distance(M.debug_compile_units_begin(),
                                       M.debug_compile_units_end());
  if (NumDebugCUs == 0)
    return false;

  std::map<GetElementPtrInst *, std::string> WorkList;
  std::set<CallInst *> BpfProbeCalls;
  computeGEPCandidates(M, WorkList, BpfProbeCalls);
  checkBpfProbeCalls(M, BpfProbeCalls);
  transformGEPCandidates(M, WorkList);

  return !WorkList.empty();
}

void BPFAbstractMemberAccess::visitDIType(const DIType *Ty) {
  if (!Ty || VisitedDITypes.find(Ty) != VisitedDITypes.end())
    return;
  VisitedDITypes.insert(Ty);

  if (const auto *CTy = dyn_cast<DICompositeType>(Ty)) {
    // Remember the named struct types
    auto Tag = CTy->getTag();
    if (Tag == dwarf::DW_TAG_structure_type || Tag == dwarf::DW_TAG_union_type) {
      if (!CTy->isForwardDecl() && CTy->getName().size())
        StructDITypes[CTy->getName()] = CTy;

      const DINodeArray Elements = CTy->getElements();
      for (const auto *Element : Elements) {
        visitDIType(cast<DIDerivedType>(Element));
      }
    } else if (Tag == dwarf::DW_TAG_array_type) {
      visitDIType(CTy->getBaseType().resolve());
    }
  } else if (const auto *DTy = dyn_cast<DIDerivedType>(Ty)) {
    if (DTy->getTag() == dwarf::DW_TAG_typedef)
      TypedefDITypes[DTy->getName()] = DTy;
    visitDIType(DTy->getBaseType().resolve());
  }
}

const DICompositeType *BPFAbstractMemberAccess::getDIStruct(std::string StructName) {
  if (StructDITypes.find(StructName) != StructDITypes.end())
    return StructDITypes[StructName];
  if (TypedefDITypes.find(StructName) != TypedefDITypes.end()) {
    const DIType *Ty = stripQualifiers(TypedefDITypes[StructName]);
    return dyn_cast<DICompositeType>(Ty);
  }
  return nullptr;
}

void BPFAbstractMemberAccess::collectDITypes(Module &M, Function &F) {
  DISubprogram *SP = F.getSubprogram();
  if (!SP)
    return;

  StructDITypes.clear();
  VisitedDITypes.clear();
  for (const DINode *DN : SP->getRetainedNodes()) {
    if (const auto *DV = dyn_cast<DILocalVariable>(DN))
      visitDIType(DV->getType().resolve());
  }

  for (const auto *Ty : SP->getUnit()->getRetainedTypes()) {
    if (const auto *RT  = dyn_cast<DIType>(Ty))
      visitDIType(RT);
  }

  for (const GlobalVariable &Global : M.globals()) {
    if (!Global.hasInitializer() && Global.hasExternalLinkage())
      continue;

    SmallVector<DIGlobalVariableExpression *, 1> GVs;
    Global.getDebugInfo(GVs);
    for (auto *GVE : GVs)
      visitDIType(GVE->getVariable()->getType().resolve());
  }

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

const DIType *BPFAbstractMemberAccess::stripQualifiers(const DIType *Ty) {
  while (Ty) {
    const auto *DTy = dyn_cast<DIDerivedType>(Ty);
    if (!DTy)
      break;

    unsigned Tag = DTy->getTag();
    if (Tag != dwarf::DW_TAG_const_type && Tag != dwarf::DW_TAG_volatile_type &&
        Tag != dwarf::DW_TAG_typedef)
       break;

    Ty = DTy->getBaseType().resolve();
  }
  return Ty;
}

// If the struct has bitfield, Index does not represent
// the position of the field in the DIStruct. Rather,
// all adjacent bitfields are collapsed into one or more types
// in the IR struct definition.
uint32_t BPFAbstractMemberAccess::computeDIMemberIndex(const DICompositeType *DIStruct,
                                                       const StructType *SType,
                                                       uint32_t STIndex) {
  const DINodeArray DIElements = DIStruct->getElements();
  uint32_t STIdx = 0, DIIdx = 0;
  int32_t OverCountedBits = 0;
  for (auto &STElement : SType->elements()) {
    if (STIdx == STIndex)
      return DIIdx;

    DIDerivedType *DIMember = cast<DIDerivedType>(DIElements[DIIdx]);
    if (!DIMember->isBitField()) {
      STIdx++;
      DIIdx++;
      continue;
    }

    // Handling bitfields
    const auto *CType = dyn_cast<CompositeType>(STElement);
    uint32_t STSize;
    if (!CType) {
      STSize = STElement->getPrimitiveSizeInBits();
    } else {
      const auto *AType = dyn_cast<ArrayType>(CType);
      assert(AType);
      STSize = AType->getNumElements() * AType->getElementType()->getPrimitiveSizeInBits();
    }

    int32_t AccuBitSize = -OverCountedBits;
    while (true) {
      uint32_t MemberBits = DIMember->getSizeInBits();
      if (AccuBitSize + MemberBits > STSize) {
        OverCountedBits = STSize - AccuBitSize;
        break;
      }
      AccuBitSize += MemberBits;
      DIIdx++;

      DIMember = cast<DIDerivedType>(DIElements[DIIdx]);
      if (!DIMember->isBitField()) {
        OverCountedBits = 0;
        break;
      }
    }

    STIdx++;
  }

  llvm_unreachable("Internal error in computeDIMemberIndex\n");
}

bool BPFAbstractMemberAccess::computeMemberAccessString(GetElementPtrInst *GEP, const StructType *SType,
    const DICompositeType *DIStruct, std::string &GVName, std::string &Prefix,
    std::vector<unsigned> &ArrayBounds) {
  // The number of initial structs and all subsequent member/array indexes
  // must be constant.
  //
  // Unions are handled differently at IR level. Trying to do a best effort
  // approximation here.
  //   . SType is the struct type at that level or nullptr if not struct type
  //   . DIStruct is the debuginfo struct type at that level or nullptr
  //     if not struct type
  //   . At the end of each iteration, next level SType and DIStruct is
  //     computed.
  bool IsUnion = false;
  std::string IntValues;
  uint32_t InitialValue = 0;
  int NumRemainingDim = -1;
  std::string StructName = DIStruct->getName();
  const ArrayType *AType = nullptr;
  for (unsigned i = 1, E = GEP->getNumOperands(); i != E; ++i) {
    const Value *V = GEP->getOperand(i);
    const auto *IntVal = dyn_cast<ConstantInt>(V);

    if (!IntVal)
      return false;

    uint64_t Index = IntVal->getValue().getLimitedValue();

    // First index is always # of structs or array of structs.
    // After that followed by array indices and struct member
    // access indices.
    if (i <= 1 + ArrayBounds.size()) {
      uint32_t R = Index;
      if (i == 1) {
        for (auto Bounds: ArrayBounds)
          R = R * Bounds;
      } else {
        for (unsigned J = i - 1, N = ArrayBounds.size(); J < N; ++J)
          R = R * ArrayBounds[J];
      }
      InitialValue += R;
      continue;
    }

    // This index is corresponding to a struct with a single member representing
    // the union.
    if (IsUnion) {
      assert(Index == 0);

      // Find union member with largest size.
      uint32_t I = 0, MaxElemSize = 0, MaxElemIndex = 0;
      const DINodeArray Elements = DIStruct->getElements();
      for (auto Element : Elements) {
        auto E = cast<DIType>(Element);
        uint64_t ElemSize = E->getSizeInBits();
        if (ElemSize > MaxElemSize) {
          MaxElemSize = ElemSize;
          MaxElemIndex = I;
        }
        I++;
      }

      // Find the element with maximum size
      const auto *DDTy = cast<DIDerivedType>(Elements[MaxElemIndex]);
      const auto *BaseTy = DDTy->getBaseType().resolve();
      const auto *CTy = dyn_cast<DICompositeType>(BaseTy);
      DIStruct = CTy;

      // If the next member is a struct, add member selector
      if (DIStruct)
        IntValues += ":" + std::to_string(MaxElemIndex);

      IsUnion = CTy && CTy->getTag() == dwarf::DW_TAG_union_type;

      if (SType) {
        StructType *SSType = dyn_cast<StructType>((SType->elements())[Index]);
        if (SSType)
          SType = SSType;
        else {
          AType = dyn_cast<ArrayType>((SType->elements())[Index]);
          SType = nullptr;
        }
      } else {
        ArrayType *AAType = dyn_cast<ArrayType>(AType->getElementType());
        if (AAType)
          AType = AAType;
        else {
          SType = dyn_cast<StructType>(AType->getElementType());
          AType = nullptr;
        }
      }

      continue;
    }

    // DIStruct may be NULL here due to proceding union
    if (!DIStruct) {
      IntValues += ":" + std::to_string(Index);
      break;
    }

    auto Tag = DIStruct->getTag();
    if (Tag == dwarf::DW_TAG_structure_type) {
      uint32_t DIIndex = computeDIMemberIndex(DIStruct, SType, Index);

      const DINodeArray Elements = DIStruct->getElements();
      assert(DIIndex < Elements.size());
      const auto *DDTy = cast<DIDerivedType>(Elements[DIIndex]);

      const auto *BaseTy = stripQualifiers(DDTy->getBaseType().resolve());
      const auto *MemberCTy = dyn_cast<DICompositeType>(BaseTy);
      DIStruct = MemberCTy;

      if (MemberCTy) {
        auto CTag = MemberCTy->getTag();
        if (CTag == dwarf::DW_TAG_union_type && !MemberCTy->isForwardDecl())
          IsUnion = true;
      }
      IntValues += ":" + std::to_string(DIIndex);
    } else if (Tag == dwarf::DW_TAG_array_type) {
      if (NumRemainingDim == -1)
        NumRemainingDim = DIStruct->getElements().size() - 1;

      if (NumRemainingDim == 0) {
        const auto *BaseTy = stripQualifiers(DIStruct->getBaseType().resolve());
        const auto *ElementCTy = dyn_cast<DICompositeType>(BaseTy);
        DIStruct = ElementCTy;
        NumRemainingDim = -1;
      } else {
        NumRemainingDim--;
      }
      IntValues += ":" + std::to_string(Index);
    } else {
      llvm_unreachable("Internal error in computeMemberAccessString: unknown DIType tag\n");
    }

    if (SType) {
      StructType *SSType = dyn_cast<StructType>((SType->elements())[Index]);
      if (SSType)
        SType = SSType;
      else {
        AType = dyn_cast<ArrayType>((SType->elements())[Index]);
        SType = nullptr;
      }
    } else {
      ArrayType *AAType = dyn_cast<ArrayType>(AType->getElementType());
      if (AAType)
        AType = AAType;
      else {
        SType = dyn_cast<StructType>(AType->getElementType());
        AType = nullptr;
      }
    }
  }

  // Construct the global variable name, which resembers
  // GetElementPtrInst.
  if (Prefix.size()) {
    GVName = Prefix +
             std::to_string(InitialValue) +
             StringRef(IntValues).str() + ":";
  } else {
    GVName = "__BTF_" + std::to_string(InitialValue) + ":" +
             (StructName + StringRef(IntValues)).str() + ":";
  }

  if (SType && DIStruct)
    STypeToDIStruct[SType->getName()] = std::make_pair(DIStruct, GVName);

  return true;
}

bool BPFAbstractMemberAccess::checkAndAddGEP(GetElementPtrInst *GEP, GEPCandidateSet &WorkList) {
  const Type *SrcElemType = GEP->getSourceElementType();

  // SrcElemType could be integer or composite type to step through
  // If integer type, no further transformations.
  const auto *IType = dyn_cast<IntegerType>(SrcElemType);
  if (IType)
    return true;

  const auto *CType = dyn_cast<CompositeType>(SrcElemType);
  if (!CType)
    return false;

  // Only handle struct and array types.
  std::vector<unsigned> ArrayBounds;
  const auto *AType = dyn_cast<ArrayType>(CType);
  while (AType) {
    ArrayBounds.push_back(AType->getNumElements());
    SrcElemType = AType->getElementType();
    CType = dyn_cast<CompositeType>(SrcElemType);
    if (!CType)
      break;
    AType = dyn_cast<ArrayType>(CType);
  }

  if (!CType)
    return false;

  const auto *SType = dyn_cast<StructType>(CType);
  if (!SType)
    return false;

  // Struct name is needed to pass info to later non-IR based passes.
  // FIXME: we are not able to handle starting type as a union yet.
  if (!SType->hasName() || !SType->getName().startswith("struct."))
    return false;

  // Find the corresponding DI struct type
  const DICompositeType *DIStruct = getDIStruct(SType->getName().substr(7));
  std::string GVName_Prefix;
  if (!DIStruct) {
    if (STypeToDIStruct.find(SType->getName()) != STypeToDIStruct.end()) {
      DIStruct = STypeToDIStruct[SType->getName()].first;
      GVName_Prefix = STypeToDIStruct[SType->getName()].second + '$';
    }
    if (!DIStruct)
      return false;
  }

  std::string GVName;
  if (!computeMemberAccessString(GEP, SType, DIStruct, GVName, GVName_Prefix, ArrayBounds))
    return false;

  WorkList[GEP] = GVName;
  return true;
}

void BPFAbstractMemberAccess::collectGEPs(Function &F,
    std::map<GetElementPtrInst *, std::set<CallInst *>> &TmpBpfProbeCalls) {
  // Collect all GEPs directly feeding into the BpfProbeCall.
  std::set<GetElementPtrInst *> GEPs;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
        GEPs.insert(GEP);
        for (User *GU : GEP->users()) {
          if (Instruction *Inst = dyn_cast<Instruction>(GU)) {
            if (auto *BI = dyn_cast<BitCastInst>(Inst)) {
              for (User *BU : BI->users()) {
                if (auto *Call = dyn_cast<CallInst>(BU)) {
                  if (isBpfProbeReadCall(Call)) {
                    TmpBpfProbeCalls[GEP].insert(Call);
                  }
                }
              }
            } else if (auto *Call = dyn_cast<CallInst>(Inst)) {
              if (isBpfProbeReadCall(Call)) {
                TmpBpfProbeCalls[GEP].insert(Call);
              }
            }
          }
        }
      }

   // Build GEP dependencies.
   bool Changed = true;
   while (Changed) {
     Changed = false;
     for (auto &GEP : GEPs) {
       for (User *GU : GEP->users()) {
         if (Instruction *Inst = dyn_cast<Instruction>(GU)) {
           // FIXME: only handle direct chaining of GetElementPtrInst insts.
           // If BitCast is involved, union is involved, skip it for now.
           if (auto *GetElemPtr = dyn_cast<GetElementPtrInst>(Inst)) {
             if (GEPDependInsts.find(GetElemPtr) == GEPDependInsts.end()) {
               // FIXME: we only did one level recursion
               // Tried complex examples, multiple levels of nested anonymous structs
               // llvm seems only have one nesting level. Will fix if later
               // more nesting level is discovered.
               if (TmpBpfProbeCalls.find(GetElemPtr) != TmpBpfProbeCalls.end()) {
                 GEPDependInsts[GetElemPtr] = GEP;
                 Changed = true;
               }
             }
           }
         }
       }
     }
   }
}

void BPFAbstractMemberAccess::processGEP(GetElementPtrInst *GEP, GEPCandidateSet &WorkList,
    std::map<GetElementPtrInst *, std::set<CallInst *>> &TmpBpfProbeCalls,
    std::set<GetElementPtrInst *> &VisitedGEPs) {
  if (VisitedGEPs.find(GEP) != VisitedGEPs.end())
    return;
  VisitedGEPs.insert(GEP);

  if (GEPDependInsts.find(GEP) != GEPDependInsts.end())
    processGEP(GEPDependInsts[GEP], WorkList, TmpBpfProbeCalls, VisitedGEPs);

  if (!checkAndAddGEP(GEP, WorkList)) {
    TmpBpfProbeCalls.erase(GEP);
  }
}

void BPFAbstractMemberAccess::processGEPs(GEPCandidateSet &WorkList,
    std::map<GetElementPtrInst *, std::set<CallInst *>> &TmpBpfProbeCalls) {
  // Process dependencies first
  std::set<GetElementPtrInst *> VisitedGEPs;
  for (auto &DEP : GEPDependInsts) {
    processGEP(DEP.second, WorkList, TmpBpfProbeCalls, VisitedGEPs);
    processGEP(DEP.first, WorkList, TmpBpfProbeCalls, VisitedGEPs);
  }

  // Process remaining GEPs in TmpBpfProbeCalls
  for (auto &BpfGEP : TmpBpfProbeCalls)
    processGEP(BpfGEP.first, WorkList, TmpBpfProbeCalls, VisitedGEPs);
}

void BPFAbstractMemberAccess::computeGEPCandidates(Module &M, GEPCandidateSet &WorkList,
  std::set<CallInst *> &BpfProbeCalls) {
  for (Function &F : M) {

    // Collect all DITypes
    collectDITypes(M, F);

    // Collect all eligible GEPs
    std::map<GetElementPtrInst *, std::set<CallInst *>> TmpBpfProbeCalls;
    collectGEPs(F, TmpBpfProbeCalls);

    // Process all GEPs
    processGEPs(WorkList, TmpBpfProbeCalls);

    // Add to BpfProbeCalls list
    for (auto Call : TmpBpfProbeCalls)
      for (auto CallInst : Call.second)
        BpfProbeCalls.insert(CallInst);
  }
}

void BPFAbstractMemberAccess::checkBpfProbeCalls(Module &M, std::set<CallInst *> &BpfProbeCalls) {
  for (Function &F : M)
    for (auto &BB : F)
      for (auto &I : BB) {
        if (auto *Call = dyn_cast<CallInst>(&I)) {
          if (!isBpfProbeReadCall(Call))
            continue;
          if (BpfProbeCalls.find(Call) == BpfProbeCalls.end()) {
            errs() << "WARNING: missing one bpf probe call in func " << F.getName() << "\n";
          }
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
    GlobalVariable *GV;
    if (GEPGlobals.find(GVName) == GEPGlobals.end()) {
      GV = new GlobalVariable(M, Type::getInt64Ty(BB->getContext()), false,
                              GlobalVariable::ExternalLinkage, NULL, GVName);
      GV->addAttribute("btf_ama");
      GEPGlobals[GVName] = GV;
    } else {
      GV = GEPGlobals[GVName];
    }

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

    GEP->replaceAllUsesWith(BCInst2);
    GEP->eraseFromParent();
  }
}
