--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2019-2020 Peter Rugg
-- Copyright (c) 2020 Alexandre Joannou
-- All rights reserved.
--
-- This software was developed by SRI International and the University of
-- Cambridge Computer Laboratory (Department of Computer Science and
-- Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
-- DARPA SSITH research programme.
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

module QuickCheckVEngine.Templates.GenCHERI (
  capDecodeTest,
  cLoadTagsTest,
  -- gen_simple_cclear, -- CHERIoT lacks cclear instr
  -- gen_simple_fpclear, -- CHERIoT lacks fpclear instr
  randomCHERITest,
  randomCHERIArithTest,
  randomCHERIRevokeTest,
  randomCHERIRVCTest
) where

import Test.QuickCheck
import Control.Monad
import RISCV
import InstrCodec
import QuickCheckVEngine.Template
import QuickCheckVEngine.Templates.Utils
import QuickCheckVEngine.Templates.GenArithmetic
import QuickCheckVEngine.Templates.GenFP
import QuickCheckVEngine.Templates.GenCompressed
import Data.Bits

cLoadTagsTest :: Template
cLoadTagsTest = loadTags 1 2

-- | Generate a CSR access from the CHERIoT test allow-list.
-- Writable CSRs may use any Zicsr instruction, while read-only CSRs are
-- accessed only with the csrr pseudo-instruction (csrrs with rs1 = x0).
legalCSRRW :: Template
legalCSRRW = random $ do
  rd <- dest
  rs1 <- src
  uimm <- bits 5
  (csrAddr, readOnly) <- frequency
--    [ (1, return (0x300, False)) -- mstatus
    [ (1, return (0x300, True)) -- mstatus
    , (1, return (0x304, True))  -- mie
--    , (1, return (0x305, True))  -- mtvec: write MTCC with CSpecialRW instead
    , (1, return (0x340, False)) -- mscratch
--    , (1, return (0x341, True))  -- mepc: write MEPCC with CSpecialRW instead
--    , (1, return (0x344, True))  -- mip
    , (1, return (0xBC1, False)) -- mshwm
    , (1, return (0xBC2, False)) -- mshwmb
    -- Give the entire unimplemented machine read/write CSR range the same
    -- aggregate selection weight as mscratch.  0xBC2 is excluded because it
    -- is implemented as mshwmb in the current CHERIoT Sail model.
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

capDecodeTest :: Template
capDecodeTest = random $ do
  let bitAppend x (a,b) = (shift x b +) <$> a b
  cap <- oneof [bits 128, -- completely random cap
                foldM bitAppend 0 [(bits,16),(bits,3),(const $ elements [0x00000,0x00001,0x00002,0x00003],18),(bits,27),(bits,64)], -- reserved otypes
                choose(40,63) >>= \exp -> foldM bitAppend 0 [(bits,16),(bits,3),(bits,18),(const $ return 1,1),(bits,9),(const $ return $ shift exp (-3),3),(bits,11),(const $ return $ exp Data.Bits..&. 0x3,3),(bits,64)] -- tricky exponents
                ]
  return $ mconcat [inst $ lui 1 0x40004,
                    inst $ slli 1 1 1,
                    li32 2 (cap Data.Bits..&. 0xffffffff),
                    inst $ sw 1 2 0,
                    li32 2 ((shift cap (-32)) Data.Bits..&. 0xffffffff),
                    inst $ sw 1 2 4,
                    li32 2 ((shift cap (-64)) Data.Bits..&. 0xffffffff),
                    inst $ sw 1 2 8,
                    li32 2 ((shift cap (-96)) Data.Bits..&. 0xffffffff),
                    inst $ sw 1 2 12,
                    inst $ clc 2 1 0, -- clc formerly known as lq
                    inst $ cgetlen 6 2,
                    -- inst $ cgetoffset 6 2, -- CHERIoT lacks cgetoffset instr
                    inst $ cgetbase 6 2,
                    inst $ cgetaddr 6 2,
                    inst $ cgethigh 6 2,
                    inst $ cgettype 6 2,
                    -- inst $ cgetflags 6 2, -- CHERIoT lacks cgetflags instr
                    inst $ cgetperm 6 2,
                    -- inst $ cbuildcap 2 3 2, -- CHERIoT lacks cbuildcap instr
                    inst $ cgettype 4 2,
                    inst $ cgettag 5 2]


genRandomCHERITest :: Integer -> Template
genRandomCHERITest baseOffset = readParams $ \param -> random $ do
  let arch = archDesc param
  srcAddr   <- src
  srcData   <- src
  tmpReg    <- src
  tmpReg2   <- src
  dest      <- dest
  imm       <- bits 12
  mop       <- elements [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                          0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
                          -- Skip LR,SC since these have non-determinism which is problematic for TestRIG
                          0x17,0x1f]
  longImm   <- (bits 20)
  fenceOp1  <- (bits 4)
  fenceOp2  <- (bits 4)
  -- srcScr    <- elements $ [0, 1, 28, 29, 30, 31] ++ (if has_s arch then [12, 13, 14, 15] else []) ++ [2]
  -- srcScr    <- elements [28, 29, 30, 31] -- CHERIoT has limited cspecialrw targets
  srcScr    <- elements [30]
  -- kliu: 29 (mtdc)) reserved for mememory acceses, 28 (mtcc) and 31 (mepcc) reserved for trap handling/resume

  -- mret causes test to stuck-in-loo
  let rv32iWithoutMret =
        concat
          [ rv32_i_arith srcAddr srcData dest imm longImm
          , rv32_i_mem srcAddr srcData dest imm fenceOp1 fenceOp2
          , rv32_i_ctrl srcAddr srcData dest imm longImm
          ]

  return $ dist [ (20, legalCHERILoadStore baseOffset)
                , (if has_a arch then 10 else 0, legalAtomicOps baseOffset)
                , (20, instUniform $ rv32iWithoutMret)
                , (10, instUniform $ rv32_xcheri arch srcAddr srcData srcScr imm mop dest)
                , (10, gen_rv_c)
                , (20, instUniform $ rv32_m srcAddr srcData dest)
                , (10, inst $ cspecialrw dest srcScr srcAddr)
                , (5, legalCSRRW)
                , (5, cspecialRWChain)
                , (10, makeShortCap)
                -- , (5, clearASR tmpReg tmpReg2)
                , (5, boundPCC tmpReg tmpReg2 imm longImm)
                , (5, inst $ cgettag dest dest)
                , (if has_nocloadtags arch then 0 else 10, loadTags srcAddr srcData)
                ]

genRandomCHERIArithTest :: Template
genRandomCHERIArithTest = random $ do
  srcAny1       <- choose (0, 15)
  srcAny2       <- choose (0, 15)
  srcCapModify  <- choose (8, 15)
  destCapModify <- choose (8, 15)
  destOther     <- choose (0, 7)
  imm           <- bits 12
  longImm       <- bits 20

  let rv32_arith =
        rv32_i_arith srcAny1 srcAny2 destOther imm longImm

      -- CHERIoT names cincaddr/cincaddrimm replace the generic CHERI
      -- names cincoffset/cincoffsetimm.  These capability-modification
      -- instructions keep both rs1 and rd in the upper register bank.
      cheri_modify =
        [ csetaddr            destCapModify srcCapModify srcAny2
        , cincaddr            destCapModify srcCapModify srcAny2
        , cincaddrimm         destCapModify srcCapModify      imm
        , csetbounds          destCapModify srcCapModify srcAny2
        , csetboundsimmediate destCapModify srcCapModify      imm
        , cseal               destCapModify srcCapModify srcAny2
        , cunseal             destCapModify srcCapModify srcAny2
        ]

      -- All remaining CHERI arithmetic instructions write only x0-x7.
      cheri_other =
        [ csethigh       destOther srcAny1 srcAny2
        , csetboundsexact destOther srcAny1 srcAny2
        , csub           destOther srcAny1 srcAny2
        , ctestsubset     destOther srcAny1 srcAny2
        , csetequalexact  destOther srcAny1 srcAny2
        ]

      cheri_arith = cheri_modify ++ cheri_other

  return $ dist
    [ (100, instUniform rv32_arith)
    , (50, instUniform cheri_arith)
    , (1, randomizeCapRegAddrs)
    ]

randomCHERIArithTest :: Template
randomCHERIArithTest = mconcat
  [ randomizeCapRegAddrs
  , repeatTillEnd genRandomCHERIArithTest
  ]

genRandomCHERITestNoJump :: Integer -> Template
genRandomCHERITestNoJump baseOffset = readParams $ \param -> random $ do
    let arch = archDesc param

    srcAddr <- src
    srcData <- src
    tmpReg  <- src
    tmpReg2 <- src
    dest    <- dest
    imm     <- bits 12
    longImm <- bits 20
    fenceOp1 <- bits 4
    fenceOp2 <- bits 4

    srcScr <- elements [30]

    let rv32iNoControl =
             rv32_i_arith srcAddr srcData dest imm longImm
          ++ [auipc dest longImm]

    return $ dist
      [ (30, legalCHERILoadStore baseOffset)
      , (20, instUniform rv32iNoControl)
      , (10, instUniform $
              rv32_xcheri_inspection srcAddr dest
           ++ rv32_xcheri_arithmetic srcAddr srcData imm dest
           ++ rv32_xcheri_misc srcAddr srcData srcScr imm dest)
      , (20, instUniform $ rv32_m srcAddr srcData dest)
      , (10, gen_rv_c)
      , (10, inst $ cspecialrw dest srcScr srcAddr)
      , (5,  legalCSRRW)
      , (10, makeShortCap)
      , (5,  inst $ cgettag dest dest)
      , (if has_nocloadtags arch then 0 else 10,
           loadTags srcAddr srcData)
      ]

-- | Generate a short sequence that stores and reloads a bounded capability
-- while allowing only CHERI arithmetic instructions to modify the memory
-- capability used as the load/store base.
legalCapRevoke :: Integer -> Template
legalCapRevoke dataCapBase = random $ do
  capReg <- suchThat src (/= 0)
  dataReg <- suchThat src (\reg -> reg /= 0 && reg /= capReg)
  tmpReg <- suchThat src
    (\reg -> reg /= 0 && reg /= capReg && reg /= dataReg)
  dataCapOffset <- choose (-128, 127)

  middleCount <- choose (0, 2)
  middle <- vectorOf middleCount $ do
    srcAddr <- src
    srcData <- src
    srcScr <- elements [30]
    imm <- bits 12
    longImm <- bits 20
    otherDst <- suchThat dest
      (\reg -> reg /= capReg && reg /= dataReg)

    elements
      (  rv32_i_arith srcAddr srcData otherDst imm longImm
      ++ rv32_xcheri_inspection srcAddr otherDst
      ++ rv32_xcheri_arithmetic srcAddr srcData imm otherDst
      ++ rv32_xcheri_misc srcAddr srcData srcScr imm otherDst
      )

  memOpCount <- choose (1, 3)
  memOps <- vectorOf memOpCount $ do
    offset <- choose (-32, 31)
    rd <- dest

    clcAlignment <- frequency
      [ (9, return 8)
      , (1, return 4)
      ]

    let normalOffset = offset
        clcOffset = normalOffset - (normalOffset `mod` clcAlignment)

    elements
      [ lw  rd capReg normalOffset
      , clc rd capReg clcOffset
      , sw  capReg dataReg normalOffset
      , csc dataReg capReg clcOffset
      ]

  let genDataReg = mconcat
        [ inst $ cspecialrw dataReg 29 0
        , li32 tmpReg (dataCapBase + dataCapOffset)
        , instSeq
            [ csetaddr dataReg dataReg tmpReg
            , csetboundsimmediate dataReg dataReg 256
            ]
        ]

  return $ mconcat
    [ inst $ cspecialrw capReg 29 0
    , genDataReg
    , instSeq middle
    , instSeq memOps
    ]

-- | Randomize four words around the revocation-bitmap word corresponding to
-- the supplied data-capability base.
randomizeShadowMem :: Integer -> Template
randomizeShadowMem shadowCapBase = random $ do
  addrReg <- suchThat src (/= 0)
  dataReg <- suchThat src (\reg -> reg /= 0 && reg /= addrReg)
  values <- vectorOf 4 (bits 32)

  let revokeBase =
        ((shadowCapBase - 0x80000000) `shiftR` 6) + 0x83000000
      writeWord (offset, value) =
        li32 dataReg value <> inst (sw addrReg dataReg offset)

  return $ mconcat
    [ inst $ cspecialrw addrReg 29 0
    , li32 dataReg revokeBase
    , inst $ csetaddr addrReg addrReg dataReg
    , mconcat $ map writeWord (zip [-8, -4, 0, 4] values)
    ]

-- | Instruction mix for revocation testing.  Control-flow instructions and
-- unrelated capability helpers are intentionally excluded.
genCHERIRevokeTest :: Integer -> Template
genCHERIRevokeTest dataCapBase = random $ do
  srcAddr <- src
  srcData <- src
  dest <- dest
  imm <- bits 12
  longImm <- bits 20
  srcScr <- elements [30]

  let allowedCsrsRO =
        [ unsafe_csrs_indexFromName "mstatus"
        , unsafe_csrs_indexFromName "mie"
        ]

  srcCsrRO <- elements allowedCsrsRO

  let rv32iNoControl =
           rv32_i_arith srcAddr srcData dest imm longImm
        ++ [auipc dest longImm]

  return $ dist
    [ (30, legalCapRevoke dataCapBase)
    , (20, instUniform rv32iNoControl)
    , (10, instUniform $
            rv32_xcheri_inspection srcAddr dest
         ++ rv32_xcheri_arithmetic srcAddr srcData imm dest
         ++ rv32_xcheri_misc srcAddr srcData srcScr imm dest)
    , (20, instUniform $ rv32_m srcAddr srcData dest)
    , (5, csrr dest srcCsrRO)
    , (1, randomizeCapRegAddrs)
    ]

-- | Random CHERIoT revocation test with one test-wide data-capability base and
-- a randomized neighborhood in the corresponding revocation bitmap.
randomCHERIRevokeTest :: Template
randomCHERIRevokeTest =
  fp_prologue $ random $ do
    shadowCapBase <- (0x80030000 +) . (* 4) <$> choose (0, 255)
    return $ mconcat
      [ randomizeCapRegAddrs
      , randomizeShadowMem shadowCapBase
      , repeatTillEnd $ genCHERIRevokeTest shadowCapBase
      ]

randomCHERIRVCTest :: Template
randomCHERIRVCTest = random $ do
  rvcInst <- bits 16
  baseOffset <- (* 4) <$> choose (0, 255)
  return $ mconcat [ -- switchEncodingMode -- Only pure CHERI mode in CHERIoT
                     genRandomCHERITest baseOffset
                   , uniform [inst $ MkInstruction rvcInst, gen_rv_c]
                   , repeatN 5 genCHERIinspection
                   ]

-- TODO: reimplement for CHERIoT using other instructions instead of cclear
-- CHERIoT lacks cclear instr
-- gen_simple_cclear :: Template
-- gen_simple_cclear = random $ do
--   mask <- bits 8
--   quarter <- bits 2
--   imm  <- bits 12
--   src1 <- src
--   src2 <- src
--   dest <- dest
--   return $ dist [ (4, prepReg64 dest)
--                 , (8, gen_rv32_i_arithmetic)
--                 , (8, instUniform $ rv64_i_arith src1 src2 dest imm)
--                 , (2, inst $ cclear quarter mask)
--                 ]

 -- CHERIoT lacks fpclear instr
-- gen_simple_fpclear :: Template
-- gen_simple_fpclear = random $ do
--   mask <- bits 8
--   quarter <- bits 2
--   return $ dist [ (8, gen_rv64_fd)
--                 , (2, inst $ fpclear quarter mask)
--                 ]

randomCHERITest :: Template
randomCHERITest =
  fp_prologue $ random $ do
    -- Persistent 10-bit, four-byte-aligned value: 0x000-0x3fc.
    baseOffset <- (* 4) <$> choose (0, 0)
    return $ mconcat
      [ randomizeCapRegAddrs
      , repeatN 150 $ genRandomCHERITestNoJump baseOffset
      , repeatTillEnd $ genRandomCHERITest baseOffset
      ]
