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

module QuickCheckVEngine.Templates.RandomTest (
  legalLoadStore,
  randomLoadStoreTest,
  randomTest
) where

import Test.QuickCheck
import RISCV
import QuickCheckVEngine.Template
import QuickCheckVEngine.Templates.Utils
import QuickCheckVEngine.Templates.GenCompressed (gen_rv_c)

-- | Initialize all nonzero RV32E registers with random 32-bit values.
randomizeIntRegs :: Template
randomizeIntRegs =
  mconcat [prepReg32 reg | reg <- [1..15]]

-- | Generate an arbitrary register index for full RV32I.
fullIntReg :: Gen Integer
fullIntReg = bits 5

-- | Initialize all nonzero RV32I registers with random 32-bit values.
randomizeFullIntRegs :: Template
randomizeFullIntRegs =
  mconcat [prepReg32 reg | reg <- [1..31]]

-- | Generate one to three naturally aligned RV32 load, store, or AMO
-- operations relative to a register initialized with 'baseOffset'.
legalLoadStore :: Integer -> Template
legalLoadStore baseOffset = readParams $ \params -> random $ do
  let desc = archDesc params

  addrReg    <- suchThat fullIntReg (/= 0)
  amoAddrReg <- suchThat fullIntReg (\r -> r /= 0 && r /= addrReg)
  opCount    <- choose (1, 3)

  memOps <- fmap concat $ vectorOf opCount $ do
    loadDest <- suchThat fullIntReg (/= addrReg)
    storeData <- fullIntReg
    aq <- bits 1
    rl <- bits 1

    let byteOp = do
          offset <- choose (-128, 127)
          op <- elements
            [ lb  loadDest addrReg offset
            , lbu loadDest addrReg offset
            , sb  addrReg storeData offset
            ]
          return [op]

        halfOp = do
          offset <- elements [-8, -6, -4, -2, 0, 2, 4, 6]
          op <- elements
            [ lh  loadDest addrReg offset
            , lhu loadDest addrReg offset
            , sh  addrReg storeData offset
            ]
          return [op]

        wordOp = do
          offset <- elements [-8, -4, 0, 4]
          op <- elements
            [ lw loadDest addrReg offset
            , sw addrReg storeData offset
            ]
          return [op]

        atomicOp = do
          -- AMO*.W has no immediate field, so first form base+offset in
          -- a temporary address register.  Both base and offset are
          -- four-byte aligned.
          offset <- elements [-8, -4, 0, 4]
          op <- elements
            [ amoswap_w loadDest amoAddrReg storeData aq rl
            , amoadd_w  loadDest amoAddrReg storeData aq rl
            , amoxor_w  loadDest amoAddrReg storeData aq rl
            , amoand_w  loadDest amoAddrReg storeData aq rl
            , amoor_w   loadDest amoAddrReg storeData aq rl
            , amomin_w  loadDest amoAddrReg storeData aq rl
            , amomax_w  loadDest amoAddrReg storeData aq rl
            , amominu_w loadDest amoAddrReg storeData aq rl
            , amomaxu_w loadDest amoAddrReg storeData aq rl
            ]
          return [addi amoAddrReg addrReg offset, op]

        -- Weight each class by its instruction count, making every
        -- individual load, store, and AMO operation equiprobable.
        opChoices =
          [ (3, byteOp)
          , (3, halfOp)
          , (2, wordOp)
          ] ++ if has_a desc then [(9, atomicOp)] else []

    frequency opChoices

  return $ li32 addrReg baseOffset <> instSeq memOps

genRandomLoadStoreTest :: Integer -> Template
genRandomLoadStoreTest baseOffset = readParams $ \params -> random $ do
  let desc = archDesc params

  src1    <- fullIntReg
  src2    <- fullIntReg
  destReg <- fullIntReg
  imm     <- bits 12
  longImm <- bits 20

  return $ dist
    [ (30, instUniform $ rv32_i_arith src1 src2 destReg imm longImm)
    , (if has_m desc then 20 else 0,
       instUniform $ rv32_m src1 src2 destReg)
    , (10, legalLoadStore baseOffset)
    , (1, randomizeFullIntRegs)
    ]

-- | Random RV32IM/A arithmetic and memory test with a test-wide base address.
randomLoadStoreTest :: Template
randomLoadStoreTest = random $ do
  -- Test-wide 32-bit value 0x08xxxxxx with bits [1:0] fixed to zero.
  low22 <- bits 22
  let baseOffset = 0x08000000 + 4 * low22

  return $
    randomizeFullIntRegs <> repeatTillEnd (genRandomLoadStoreTest baseOffset)

-- | 'randomTest' provides a 'Template' for a random test
randomTest :: Template
randomTest = readParams $ \params ->
  fp_prologue $ randomizeIntRegs <> go (archDesc params)
  where
    go desc = random $ do
      remaining <- getSize
      srcAddr   <- src
      srcData   <- src
      dest      <- dest
      imm       <- bits 12
      longImm   <- bits 20
      fenceOp1  <- bits 4
      fenceOp2  <- bits 4
      csrAddr   <- frequency [ -- (1, return (unsafe_csrs_indexFromName "mccsr")) -- CHERIoT lacks capability CSRs
                               (1, return (unsafe_csrs_indexFromName "mcause"))
                             , (1, bits 12) ]
      let baseTests =
            [ (if remaining > 10 then 1 else 0, legalLoad)
            , (if remaining > 10 then 1 else 0, legalStore)
            , (10, instUniform $ rv32_i srcAddr srcData dest imm longImm fenceOp1 fenceOp2)
            ]

          mTests =
            if has_m desc
              then [(10, instUniform $ rv32_m srcAddr srcData dest)]
              else []

          cTests =
            if has_c desc
              then [(10, gen_rv_c)]
              else []

          recursiveTests =
            [ (if remaining > 10 then 1 else 0,
               surroundWithMemAccess (go desc))
            ]

          test = dist (baseTests ++ mTests ++ cTests ++ recursiveTests)

      return $
        if remaining <= 0
          then mempty
          else
            if remaining > 10
              then test <> go desc
              else test
