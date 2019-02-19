//===------ BPFMILoopInstGen.cpp - MI Loop Instruction Generation  --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This pass generate loop instructions.
//
//===----------------------------------------------------------------------===//

#include "BPF.h"
#include "BPFTargetMachine.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineLoopInfo.h"

using namespace llvm;

#define DEBUG_TYPE "bpf-mi-loop-inst-gen"

namespace {

struct BPFMIPreEmitLoopInstGen : public MachineFunctionPass {
public:
  static char ID;
  BPFMIPreEmitLoopInstGen() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "BPF Loop Instruction Generation"; }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<MachineLoopInfo>();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  // Main entry point for this pass.
  bool runOnMachineFunction(MachineFunction &MF) override;

private:
  void InsertEndLoopInst(MachineLoop *Loop, MachineBasicBlock &BB,
                         MachineInstr &I, const BPFInstrInfo *TII);
};

void BPFMIPreEmitLoopInstGen::InsertEndLoopInst(MachineLoop *Loop,
                                                MachineBasicBlock &BB,
                                                MachineInstr &I,
                                                const BPFInstrInfo *TII) {
  LLVM_DEBUG(dbgs() << "Insert end_loop inst in Loop:\n";
             Loop->dump();
             dbgs() << '\n');

  BuildMI(BB, I, I.getDebugLoc(), TII->get(BPF::END_LOOP));
}

bool BPFMIPreEmitLoopInstGen::runOnMachineFunction(MachineFunction &MF) {
  if (skipFunction(MF.getFunction()))
    return false;

  LLVM_DEBUG(dbgs() << "*** BPF PreEmit Loop Instruction Generation Pass ***\n"
                    << "*** Function: " << MF.getName() << '\n');

  bool Changed = false;
  const auto &MLI = getAnalysis<MachineLoopInfo>();
  const BPFInstrInfo *TII = MF.getSubtarget<BPFSubtarget>().getInstrInfo();
  for (auto &MBB : MF) {
    MachineLoop *Loop = MLI.getLoopFor(&MBB);
    if (!Loop)
      continue;

    MachineBasicBlock *LatchBlock = Loop->getLoopLatch();
    if (!LatchBlock || LatchBlock != &MBB)
      continue;

    // The conditional branch, if found, should be the backedge.
    //
    // It may be the last inst in the basic block, then we
    // need to find the non-header successor and insert
    // an end_loop inst in the beginning of that successor.
    //
    // Or the conditional branch may be followed by
    // unconditional jump in the same basic block.
    // In this case, an end_loop inst is inserted before
    // the unconditional jump inst.
    bool ToInsertInst = false;
    for (auto &MI : MBB) {
      if (MI.isConditionalBranch()) {
        ToInsertInst = true;
      } else if (ToInsertInst) {
        InsertEndLoopInst(Loop, MBB, MI, TII);
        Changed = true;
        ToInsertInst = false;
        break;
      }
    }

    if (ToInsertInst) {
      // Go through successors.
      for (auto Succ : MBB.successors()) {
        if (Succ != Loop->getHeader()) {
          InsertEndLoopInst(Loop, *Succ, Succ->instr_front(), TII);
          Changed = true;
          break;
        }
      }
    }
  }

  return Changed;
};

} // end default namespace

INITIALIZE_PASS(BPFMIPreEmitLoopInstGen, DEBUG_TYPE,
                "BPF PreEmit Loop Instruction Generation", false, false)

char BPFMIPreEmitLoopInstGen::ID = 0;
FunctionPass* llvm::createBPFMIPreEmitLoopInstGenPass()
{
  return new BPFMIPreEmitLoopInstGen();
}
