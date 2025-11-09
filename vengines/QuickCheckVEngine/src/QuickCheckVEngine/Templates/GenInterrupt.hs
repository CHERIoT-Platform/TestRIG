--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2024 lowRISC contributors
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

-- Interrupt tests

module QuickCheckVEngine.Templates.GenInterrupt (
  genInterruptTest
) where

import RISCV.RV32_I
import RISCV.RV32_Zicsr
import RISCV.RV32_Xcheri
import RISCV.RV_CSRs
import QuickCheckVEngine.Instrlike
import QuickCheckVEngine.Template
import QuickCheckVEngine.Templates.Utils
import QuickCheckVEngine.Templates.GenAll
import Data.Bits

msiFixedTest :: Template
msiFixedTest = random $ do
  return $ mconcat [
                     inst $ auipc 8 4, -- read pcc capability, offset to create some target address
                     inst $ cspecialrw 4 28 8, -- write new trap capability in mtcc
                     inst $ csrrsi 4 (unsafe_csrs_indexFromName "mie") (1 `shiftL` 3) , -- set Machine Software Interrupt Enable
                     inst $ csrrsi 4 (unsafe_csrs_indexFromName "mstatus") (1 `shiftL` 3) , -- set global Machine Interrupt Enable
                     intReq 3, -- 3 = Machine Software Interrupt
                     intBar,
                     inst $ csrrs 10 (unsafe_csrs_indexFromName "mcause") 0, -- check mcause
                     inst $ csrrs 10 (unsafe_csrs_indexFromName "mtval") 0, -- check mtval
                     inst $ csrrs 10 (unsafe_csrs_indexFromName "mip") 0, -- check Machine Interrupts Pending
                     inst $ cspecialrw 10 31 0, -- check mepcc
                     inst $ cspecialrw 5 29 0, -- load mtdc
                     inst $ lui 6 (0x02000000 `shiftR` 12), -- load CLINT base address
                     inst $ csetaddr 7 5 6, -- build capability to CLINT base
                     inst $ lw 10 7 0, -- check Machine Software Interrupt
                     inst $ sw 7 0 0, -- clear Machine Software Interrupt
                     inst $ mret, -- return from trap
                     inst $ addi 0 0 0 -- nop
                   ]

msiRandTest :: Template
msiRandTest = random $ do
  tmpReg1   <- src
  tmpReg2   <- src
  tmpReg3   <- dest
  imm       <- bits 12
  return $ mconcat  [ (noShrink $ instSeq [
                        auipc tmpReg1 0, -- load pcc capability
                        addi tmpReg2 0 ((imm .&. 0xFFF0) `shiftR` 4), -- | load randomised trap address offset,
                        slli tmpReg2 tmpReg2 4,                       -- | fit within in RVFI 64KiB sram (usually)
                        addi tmpReg2 tmpReg2 (imm .&. 0xC),           -- | and 4-byte aligned
                        cincaddr tmpReg3 tmpReg1 tmpReg2, -- create capability to trap entry
                        cspecialrw tmpReg1 28 tmpReg3, -- write new trap capability to mtcc
                        csrrsi tmpReg1 (unsafe_csrs_indexFromName "mie") (1 `shiftL` 3), -- set Machine Software Interrupt Enable
                        csrrsi tmpReg1 (unsafe_csrs_indexFromName "mstatus") (1 `shiftL` 3) -- set global Machine Interrupt Enable
                      ]),
                      genAll,
                      intReq 3, -- set mip[3] (Machine Software Interrupt)
                      intBar,
                      genAll,
                      (noShrink $ instSeq [
                        cspecialrw tmpReg1 29 0, -- load mtdc
                        lui tmpReg2 (0x02000000 `shiftR` 12), -- load CLINT base address
                        csetaddr tmpReg3 tmpReg1 tmpReg2, -- create capability to CLINT base
                        sw tmpReg3 0 0, -- clear Machine Software Interrupt
                        mret -- return from trap
                      ]),
                      genAll
                    ]

genInterruptTest :: Template
genInterruptTest = msiRandTest
