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
