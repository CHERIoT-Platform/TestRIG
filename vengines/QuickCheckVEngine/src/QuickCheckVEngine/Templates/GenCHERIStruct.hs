--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2019-2020 Peter Rugg
-- Copyright (c) 2020 Alexandre Joannou
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.
--

module QuickCheckVEngine.Templates.GenCHERIStruct (
  spReg,
  raReg,
  strBranch,
  strCHERILoadStore,
  strCSRRW,
  strRandomizeCapRegAddr,
  gen_rv_c_simple,
  legalSubroutine,
  strRandomTest
) where

import Test.QuickCheck
import RISCV
import QuickCheckVEngine.Template
import QuickCheckVEngine.Templates.Utils
import Data.Bits

-- | Registers reserved for the structured control-flow templates.
spReg, raReg :: Integer
spReg = 2
raReg = 1

protectedRegs :: [Integer]
protectedRegs = [spReg]

protectedDest :: Gen Integer
protectedDest = suchThat dest (`notElem` protectedRegs)

-- | Generate a forward or backward branch whose setup and intervening
-- arithmetic do not overwrite its temporary or the stack register.
strBranch :: Template
strBranch = random $ do
  branchCount <- choose (1, 2)
  branchConfigs <- vectorOf branchCount $ do
    (branchOp, backwardMask, backwardTmpValue) <- elements
      [ (beq,  0x0f, 8)
      , (bne,  0x01, 0)
      , (blt,  0x0f, 2)
      , (bltu, 0x0f, 2)
      , (bge,  0x0f, 13)
      , (bgeu, 0x0f, 13)
      ]
    isBackward <- elements [False, True]
    let (mask, tmpValue) =
          if isBackward
            then (backwardMask, backwardTmpValue)
            else (0x0f, 8)
    return (branchOp, mask, tmpValue, isBackward)

  tmp1 <- suchThat dest $ \reg ->
    reg /= 0 && reg `notElem` protectedRegs
  tmp2 <- suchThat dest $ \reg ->
    reg /= 0 && reg `notElem` (tmp1 : protectedRegs)
  tmp3 <- suchThat dest $ \reg ->
    reg /= 0 && reg `notElem` (tmp2 : tmp1 : protectedRegs)
  tmp4 <- suchThat dest $ \reg ->
    reg /= 0 && reg `notElem` (tmp3 : tmp2 : tmp1 : protectedRegs)

  middleCount <- choose (1, 3)
  middle <- vectorOf middleCount $ do
    src1 <- src
    src2 <- src
    otherDst <- suchThat dest $ \reg ->
      reg `notElem` [spReg, tmp1, tmp2, tmp3, tmp4]
    imm <- bits 12
    longImm <- bits 20
    elements $
         rv32_i_arith src1 src2 otherDst imm longImm
      ++ rv32_xcheri_arithmetic src1 src2 imm otherDst

  -- Put every mcycle read at the start so build_struct_elf can use the
  -- consecutive reads as the branch-group marker.  The remaining setup blocks
  -- precede the unchanged arithmetic middle, and all branches remain at the
  -- end.  A backward branch targets its corresponding mcycle read;
  -- build_struct_elf preserves the placeholder direction when assigning the
  -- final target.
  let tmpPairs = [(tmp1, tmp2), (tmp3, tmp4)]
      activePairs = take branchCount tmpPairs
      mcycleReads =
        [ csrrs lhs 0xB00 0
        | (lhs, _) <- activePairs
        ]
      setupInstructions = concat
        [ [ andi lhs lhs mask
          , addi rhs 0 tmpValue
          ]
        | ((_, mask, tmpValue, _), (lhs, rhs)) <-
            zip branchConfigs activePairs
        ]
      branchInstructions =
        [ let mcycleIndex = branchIndex
              branchPosition = 3 * branchCount + middleCount + branchIndex
              backwardDistance = branchPosition - mcycleIndex
              branchImm =
                if isBackward
                  then (0x1000 - 2 * toInteger backwardDistance)
                       Data.Bits..&. 0x0fff
                  else 2
          in branchOp lhs rhs branchImm
        | (branchIndex, ((branchOp, _, _, isBackward), (lhs, rhs))) <-
            zip [0..] (zip branchConfigs activePairs)
        ]

  return $ instSeq $
    mcycleReads ++ setupInstructions ++ middle ++ branchInstructions

-- | Generate a CSR access without writing either protected register.
strCSRRW :: Template
strCSRRW = random $ do
  rd <- protectedDest
  rs1 <- src
  uimm <- bits 5
  (csrAddr, readOnly) <- frequency
    [ (1, return (0x300, True))  -- mstatus
    , (1, return (0x304, True))  -- mie
    , (1, return (0x340, False)) -- mscratch
    , (1, return (0xBC1, False)) -- mshwm
    , (1, return (0xBC2, False)) -- mshwmb
    , (1, do csr <- choose (0xBC5, 0xBFF)
             return (csr, False))
    ]

  if readOnly
    then return $ csrr rd csrAddr
    else elements
      [ inst $ csrrw  rd csrAddr rs1
      , inst $ csrrs  rd csrAddr rs1
      , inst $ csrrc  rd csrAddr rs1
      , inst $ csrrwi rd csrAddr uimm
      , inst $ csrrsi rd csrAddr uimm
      , inst $ csrrci rd csrAddr uimm
      ]

-- | Generate legal CHERIoT memory sequences while reserving spReg.
strCHERILoadStore :: Integer -> Template
strCHERILoadStore baseOffset = random $ do
  capReg <- suchThat src $ \reg ->
    reg /= 0 && reg `notElem` protectedRegs
  dataReg <- suchThat dest $ \reg ->
    reg /= 0 && reg /= capReg && reg `notElem` protectedRegs
  count <- choose (0, 2)

  middle <- vectorOf count $ do
    srcAddr <- src
    srcData <- src
    srcScr <- elements [30]
    imm <- bits 12
    longImm <- bits 20
    otherDst <- suchThat dest $ \reg ->
      reg `notElem` (capReg : protectedRegs)
    elements
      (  rv32_i_arith srcAddr srcData otherDst imm longImm
      ++ rv32_xcheri_inspection srcAddr otherDst
      ++ rv32_xcheri_arithmetic srcAddr srcData imm capReg
      ++ rv32_xcheri_misc srcAddr srcData srcScr imm otherDst
      )

  memOpCount <- choose (1, 3)
  memOps <- vectorOf memOpCount $ do
    offset <- choose (0x0, 0x7f)
    clcMask <- frequency
      [ (9, return 0x7f8)
      , (1, return 0x7fc)
      ]
    let normalOffset = baseOffset + offset
        clcOffset = normalOffset Data.Bits..&. clcMask
    frequency
      [ (1, return $ lb  dataReg capReg normalOffset)
      , (1, return $ lbu dataReg capReg normalOffset)
      , (1, return $ lh  dataReg capReg normalOffset)
      , (1, return $ lhu dataReg capReg normalOffset)
      , (1, return $ lw  dataReg capReg normalOffset)
      , (4, return $ clc dataReg capReg clcOffset)
      , (1, return $ sb  capReg dataReg normalOffset)
      , (1, return $ sh  capReg dataReg normalOffset)
      , (1, return $ sw  capReg dataReg normalOffset)
      , (4, return $ csc dataReg capReg clcOffset)
      ]

  arithCount <- choose (0, 2)
  arithOps <- vectorOf arithCount $ do
    srcData <- src
    imm <- bits 12
    otherDst <- suchThat dest $ \reg ->
      reg `notElem` (capReg : protectedRegs)
    elements $ rv32_xcheri_arithmetic dataReg srcData imm otherDst

  return $ instSeq $
    [cspecialrw capReg 29 0] ++ middle ++ memOps ++ arithOps

-- | Randomize capability-register addresses without writing spReg.
strRandomizeCapRegAddr :: Template
strRandomizeCapRegAddr = random $ do
  let randomizedRegs = filter (`notElem` protectedRegs) [2..14]
      addressTmpReg = 15
      dataTmpReg = 13
  values <- vectorOf (1 + length randomizedRegs) (bits 32)

  let loadValue :: Integer -> Integer -> [Instruction]
      loadValue reg value =
        let upper20 =
              ((value + 0x800) `shiftR` 12) Data.Bits..&. 0xfffff
            lower12 =
              value Data.Bits..&. 0xfff
        in
          [ lui  reg upper20
          , addi reg reg lower12
          ]

      x1Value = (head values) Data.Bits..&. 0x00ffff00

      x1Sequence =
        [ cspecialrw raReg 29 0
        ]
        ++ loadValue addressTmpReg x1Value
        ++
        [ csetaddr   raReg raReg addressTmpReg
        , cspecialrw 0 29 raReg
        ]
        ++ loadValue dataTmpReg 0xffffff00
        ++
        [ csetaddr   raReg raReg dataTmpReg
        , cspecialrw dataTmpReg 29 0
        , sw         raReg dataTmpReg 0
        ]
        ++ loadValue dataTmpReg 0x100
        ++
        [ sw         raReg dataTmpReg 0
        ]

      makeSequence :: (Integer, Integer) -> [Instruction]
      makeSequence (reg, value) =
        let scr = if odd reg then 28 else 29
        in
          [ cspecialrw reg scr 0
          ]
          ++ loadValue addressTmpReg value
          ++
          [ csetaddr reg reg addressTmpReg
          ]

      remainingSequences =
        concatMap makeSequence $ zip randomizedRegs (tail values)

  return $ instSeq $ x1Sequence ++ remainingSequences

-- | Generate compressed arithmetic/register instructions only.  Loads,
-- stores, jumps, branches, traps, and instructions that write spReg
-- are deliberately omitted.
gen_rv_c_simple :: Template
gen_rv_c_simple = random $ do
  imm <- genCompressed_imm
  nzimm <- genCompressed_nzimm
  nzuimm <- genCompressed_nzuimm

  rdPrime <- elements
    [ reg - 8 | reg <- [8..15], reg `notElem` protectedRegs ]
  rs2Prime <- elements [0..7]
  rdNz <- elements
    [ reg | reg <- [1..15], reg `notElem` protectedRegs ]
  rdNzN2 <- elements
    [ reg | reg <- 1:[3..15], reg `notElem` protectedRegs ]
  rs2Nz <- elements [1..15]

  return $ instUniform
    [ c_addi4spn rdPrime nzuimm
    , c_nop nzimm
    , c_addi rdNz nzimm
    , c_li rdNz imm
    , c_lui rdNzN2 nzimm
    , c_srli64 rdPrime
    , c_srli rdPrime nzuimm
    , c_srai64 rdPrime
    , c_srai rdPrime nzuimm
    , c_andi rdPrime imm
    , c_sub rdPrime rs2Prime
    , c_xor rdPrime rs2Prime
    , c_or rdPrime rs2Prime
    , c_and rdPrime rs2Prime
    , c_slli64 rdNz
    , c_slli rdNz nzuimm
    , c_mv rdNz rs2Nz
    , c_add rdNz rs2Nz
    ]

-- | One weighted operation in the body of a structured subroutine.
strSubroutineMiddle :: Template
strSubroutineMiddle = random $ do
  srcAddr <- src
  srcData <- src
  destReg <- protectedDest
  imm <- bits 12
  longImm <- bits 20
  srcScr <- elements [30]

  let rv32iNoControl =
           rv32_i_arith srcAddr srcData destReg imm longImm
        ++ [auipc destReg longImm]

      cheriNoControl =
           rv32_xcheri_inspection srcAddr destReg
        ++ rv32_xcheri_arithmetic srcAddr srcData imm destReg
        ++ rv32_xcheri_misc srcAddr srcData srcScr imm destReg

  return $ dist
    [ (10, strCHERILoadStore 0)
    , (20, instUniform rv32iNoControl)
    , (20, instUniform cheriNoControl)
    , (20, instUniform $ rv32_m srcAddr srcData destReg)
    , (5,  inst $ cspecialrw destReg srcScr srcAddr)
    , (5,  strCSRRW)
    , (20, gen_rv_c_simple)
    , (20, strBranch)
    ]

-- | Arithmetic operations permitted after the first subroutine call.  Preserve
-- both the stack and return-address registers so the epilogue remains valid.
strSubroutineTailArithmetic :: Template
strSubroutineTailArithmetic = random $ do
  src1 <- src
  src2 <- src
  destReg <- suchThat dest (`notElem` [spReg, raReg])
  imm <- bits 12
  longImm <- bits 20
  return $ instUniform $
       rv32_i_arith src1 src2 destReg imm longImm
    ++ rv32_xcheri_arithmetic src1 src2 imm destReg

-- | Structured subroutine with a capability stack push/pop and return.
legalSubroutine :: Template
legalSubroutine =
  noShrink stackPush
  <> subroutineBody
  <> noShrink stackPop
  where
    subroutineBody = random $ do
      middleOpCount <- choose (50, 100)
      return $
        repeatN middleOpCount strSubroutineMiddle
        -- Keep all calls in a tail region after every generated branch.  Only
        -- arithmetic operations may separate the calls or follow the last one.
        <> subroutineCallTail
    subroutineCallTail = random $ do
      callCount <- choose (1, 3)
      arithmeticCounts <- vectorOf callCount $ choose (0, 2)
      return $ mconcat
        [ noShrink mandatoryTailCall
          <> repeatN arithmeticCount strSubroutineTailArithmetic
        | arithmeticCount <- arithmeticCounts
        ]
    mandatoryTailCall = uniform
      [ inst $ c_jal 1
      , inst $ jal raReg 2
      ]
    stackPush = instSeq
      [ csc raReg spReg 0
      , cincaddrimm spReg spReg 0xff8
      ]
    stackPop = instSeq
      [ cincaddrimm spReg spReg 8
      , clc raReg spReg 0
      ]
      <> uniform
        [ inst $ jalr 0 raReg 0
        , inst $ c_jr raReg
        ]

-- | Initialize the structured registers, randomize the remaining capability
-- registers, and generate between three and ten structured subroutines.
strRandomTest :: Template
strRandomTest = random $ do
  subroutineCount <- choose (5, 10)
  return $
    noShrink initializeStructuredRegs
    <> noShrink strRandomizeCapRegAddr
    <> noShrink (instSeq [jal raReg 0, jal raReg 0, jal raReg 0])
    <> repeatN subroutineCount legalSubroutine
  where
    addressTmpReg = 15
    initializeStructuredRegs =
      instSeq
        [cspecialrw spReg 29 0]
      <> li32 addressTmpReg 0x808f0000
      <> inst (csetaddr spReg spReg addressTmpReg)
