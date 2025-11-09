--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2018 Jonathan Woodruff
-- Copyright (c) 2018 Hesham Almatary
-- Copyright (c) 2018 Matthew Naylor
-- Copyright (c) 2019-2020 Alexandre Joannou
-- Copyright (c) 2020 Peter Rugg
-- Copyright (c) 2021-2022 Franz Fuchs
-- All rights reserved.
--
-- This software was developed by SRI International and the University of
-- Cambridge Computer Laboratory (Department of Computer Science and
-- Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
-- DARPA SSITH research programme.
--
-- This software was partly developed by the University of Cambridge
-- Computer Laboratory as part of the Partially-Ordered Event-Triggered
-- Systems (POETS) project, funded by EPSRC grant EP/N031768/1.
--
-- This software was developed by the University of  Cambridge
-- Department of Computer Science and Technology under the
-- SIPP (Secure IoT Processor Platform with Remote Attestation)
-- project funded by EPSRC: EP/S030868/1
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

{-|
    Module      : RISCV.RV32_Xcheri
    Description : RISC-V CHERI extension

    The 'RISCV.RV32_Xcheri' module provides the description of the RISC-V CHERI
    extension
-}

module RISCV.RV32_Xcheri (
-- * RISC-V CHERI, instruction definitions
  cgetperm
, cgettype
, cgetbase
, cgetlen
, cgettag
-- , cgetsealed -- CHERIoT lacks cgetsealed instr
-- , cgetoffset -- CHERIoT lacks cgetoffset instr
-- , cgetflags -- CHERIoT lacks cgetflags instr
, cgetaddr
, cgethigh
, cgettop
, cseal
, cunseal
, candperm
-- , csetflags -- CHERIoT lacks csetflags instr
-- , csetoffset -- CHERIoT lacks csetoffset instr
, csetaddr
, csethigh
-- , cincoffset -- CHERIoT replaces cincoffset with cincaddr
, cincaddr
-- , cincoffsetimmediate -- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
, cincaddrimm            -- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
, csetbounds
, csetboundsexact
, csetboundsimmediate
, ccleartag
-- , cbuildcap -- CHERIoT lacks cbuildcap instr
-- , ccopytype -- CHERIoT lacks ccopytype instr
-- , ccseal -- CHERIoT lacks ccseal instr
-- , csealentry -- CHERIoT lacks csealentry instr
, cloadtags -- CHERIoT lacks cloadtags instr, disabled using has_nocloadtags rather than code removal
-- , ctoptr -- CHERIoT lacks ctoptr instr
-- , cfromptr -- CHERIoT lacks cfromptr instr
, csub
, cmove
-- , jalr_cap -- CHERIoT lacks jalr_cap (jalr.cap) instr
-- , cinvoke -- CHERIoT lacks cinvoke instr
, ctestsubset
, csetequalexact
, cspecialrw
, auicgp
-- , auipcc -- auipcc uses same encoding as auipc, so just use auipc
-- , clear -- CHERIoT lacks clear instr
-- , cclear -- CHERIoT lacks cclear instr
-- , fpclear -- CHERIoT lacks fpclear instr
, croundrepresentablelength
, crepresentablealignmentmask
-- , cload -- CHERIoT lacks mem loads w/explicit addr
-- , cstore -- CHERIoT lacks mem stores w/explicit addr
, clc -- clc formerly known as lq
, csc -- csc formerly known as sq (note: swapped reg order)
-- , lr_q -- CHERIoT lacks lr_q (lr.c/q) atomic instr
-- , sc_q -- CHERIoT lacks sc_q (sc.c/q) atomic instr
-- , amoswap_q -- CHERIoT lacks amoswap_q (amoswap.c/q) atomic instr
-- * RISC-V CHERI, others
, rv32_xcheri_disass
, rv32_xcheri_extract
, rv32_xcheri_shrink
, rv32_xcheri
, rv32_xcheri_inspection
, rv32_xcheri_arithmetic
, rv32_xcheri_misc
, rv32_xcheri_mem
, rv32_a_xcheri
-- , rv32_xcheri_control -- CHERIoT lacks cinvoke and jalr_cap (jalr.cap) instr
) where

import RISCV.Helpers (reg, int, prettyR, prettyI, prettyL, prettyS, prettyR_2op, prettyR_A_1op, prettyR_A, prettyU, ExtractedRegs)
import InstrCodec (DecodeBranch, (-->), encode, Instruction)
import RISCV.RV32_I
import RISCV.ArchDesc

-- Capability Inspection
cgetperm_raw                       =                                        "1111111 00000 cs1[4:0] 000 rd[4:0] 1011011"
cgetperm rd cs1                    = encode cgetperm_raw                                   cs1          rd
cgettype_raw                       =                                        "1111111 00001 cs1[4:0] 000 rd[4:0] 1011011"
cgettype rd cs1                    = encode cgettype_raw                                   cs1          rd
cgetbase_raw                       =                                        "1111111 00010 cs1[4:0] 000 rd[4:0] 1011011"
cgetbase rd cs1                    = encode cgetbase_raw                                   cs1          rd
cgetlen_raw                        =                                        "1111111 00011 cs1[4:0] 000 rd[4:0] 1011011"
cgetlen rd cs1                     = encode cgetlen_raw                                    cs1          rd
cgettag_raw                        =                                        "1111111 00100 cs1[4:0] 000 rd[4:0] 1011011"
cgettag rd cs1                     = encode cgettag_raw                                    cs1          rd
-- CHERIoT lacks cgetsealed instr
-- cgetsealed_raw                     =                                        "1111111 00101 cs1[4:0] 000 rd[4:0] 1011011"
-- cgetsealed rd cs1                  = encode cgetsealed_raw                                 cs1          rd
-- CHERIoT lacks cgetoffset instr
-- cgetoffset_raw                     =                                        "1111111 00110 cs1[4:0] 000 rd[4:0] 1011011"
-- cgetoffset rd cs1                  = encode cgetoffset_raw                                 cs1          rd
-- CHERIoT lacks cgetflags instr
-- cgetflags_raw                      =                                        "1111111 00111 cs1[4:0] 000 rd[4:0] 1011011"
-- cgetflags rd cs1                   = encode cgetflags_raw                                  cs1          rd
cgetaddr_raw                       =                                        "1111111 01111 cs1[4:0] 000 rd[4:0] 1011011"
cgetaddr rd cs1                    = encode cgetaddr_raw                                   cs1          rd
cgethigh_raw                       =                                        "1111111 10111 cs1[4:0] 000 rd[4:0] 1011011"
cgethigh rd cs1                    = encode cgethigh_raw                                   cs1          rd
cgettop_raw                        =                                        "1111111 11000 cs1[4:0] 000 rd[4:0] 1011011"
cgettop rd cs1                     = encode cgettop_raw                                    cs1          rd

-- Capability Modification
cseal_raw                          =                                        "0001011 cs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
cseal cd cs1 cs2                   = encode cseal_raw                                cs2      cs1          cd
cunseal_raw                        =                                        "0001100 cs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
cunseal cd cs1 cs2                 = encode cunseal_raw                              cs2      cs1          cd
candperm_raw                       =                                        "0001101 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
candperm cd cs1 rs2                = encode candperm_raw                             rs2      cs1          cd
-- CHERIoT lacks csetflags instr
-- csetflags_raw                      =                                        "0001110 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
-- csetflags cd cs1 rs2               = encode csetflags_raw                            rs2      cs1          cd
-- CHERIoT lacks csetoffset instr
-- csetoffset_raw                     =                                        "0001111 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
-- csetoffset cd cs1 rs2              = encode csetoffset_raw                           rs2      cs1          cd
csetaddr_raw                       =                                        "0010000 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
csetaddr cd cs1 rs2                = encode csetaddr_raw                             rs2      cs1          cd
csethigh_raw                       =                                        "0010110 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
csethigh cd cs1 rs2                = encode csethigh_raw                             rs2      cs1          cd
-- CHERIoT replaces cincoffset with cincaddr
-- cincoffset_raw                     =                                        "0010001 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
-- cincoffset cd cs1 rs2              = encode cincoffset_raw                           rs2      cs1          cd
cincaddr_raw                       =                                        "0010001 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
cincaddr cd cs1 rs2                = encode cincaddr_raw                             rs2      cs1          cd
-- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
-- cincoffsetimmediate_raw            =                                        "imm[11:0] cs1[4:0] 001 cd[4:0] 1011011"
-- cincoffsetimmediate cd cs1 imm     = encode cincoffsetimmediate_raw          imm       cs1          cd
cincaddrimm_raw                    =                                        "imm[11:0] cs1[4:0] 001 cd[4:0] 1011011"
cincaddrimm cd cs1 imm             = encode cincaddrimm_raw                  imm       cs1          cd
csetbounds_raw                     =                                        "0001000 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
csetbounds cd cs1 rs2              = encode csetbounds_raw                           rs2      cs1          cd
csetboundsexact_raw                =                                        "0001001 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
csetboundsexact cd cs1 rs2         = encode csetboundsexact_raw                      rs2      cs1          cd
csetboundsimmediate_raw            =                                        "imm[11:0] cs1[4:0] 010 cd[4:0] 1011011"
csetboundsimmediate cd cs1 imm     = encode csetboundsimmediate_raw          imm       cs1          cd
ccleartag_raw                      =                                        "1111111 01011 cs1[4:0] 000 cd[4:0] 1011011"
ccleartag cd cs1                   = encode ccleartag_raw                                  cs1          cd
-- CHERIoT lacks cbuildcap instr
-- cbuildcap_raw                      =                                        "0011101 cs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
-- cbuildcap cd cs1 cs2               = encode cbuildcap_raw                            cs2      cs1          cd
-- CHERIoT lacks ccopytype instr
-- ccopytype_raw                      =                                        "0011110 cs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
-- ccopytype cd cs1 cs2               = encode ccopytype_raw                            cs2      cs1          cd
-- CHERIoT lacks ccseal instr
-- ccseal_raw                         =                                        "0011111 cs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
-- ccseal cd cs1 cs2                  = encode ccseal_raw                               cs2      cs1          cd
-- CHERIoT lacks csealentry instr
-- csealentry_raw                     =                                        "1111111 10001 cs1[4:0] 000 cd[4:0] 1011011"
-- csealentry cd cs1                  = encode csealentry_raw                                 cs1          cd
-- CHERIoT lacks cloadtags instr, disabled using has_nocloadtags rather than code removal
cloadtags_raw                      =                                        "1111111 10010 cs1[4:0] 000 rd[4:0] 1011011"
cloadtags rd cs1                   = encode cloadtags_raw                                  cs1          rd


-- Capability Pointer Arithmetic
-- CHERIoT lacks ctoptr instr
-- ctoptr_raw                         =                                        "0010010 cs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
-- ctoptr cd cs1 cs2                  = encode ctoptr_raw                               cs2      cs1          cd
-- CHERIoT lacks cfromptr instr
-- cfromptr_raw                       =                                        "0010011 rs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
-- cfromptr cd cs1 rs2                = encode cfromptr_raw                             rs2      cs1          cd
csub_raw                           =                                        "0010100 cs2[4:0] cs1[4:0] 000 cd[4:0] 1011011"
csub cd cs1 cs2                    = encode csub_raw                                 cs2      cs1          cd
cmove_raw                          =                                        "1111111 01010 cs1[4:0] 000 cd[4:0] 1011011"
cmove cd cs1                       = encode cmove_raw                                      cs1          cd
cspecialrw_raw                     =                                        "0000001 cSP[4:0] cs1[4:0] 000 cd[4:0] 1011011"
cspecialrw cd cSP cs1              = encode cspecialrw_raw                           cSP      cs1          cd
auicgp_raw                         =                                        "imm[31:12] cd[4:0] 1111011"
auicgp cd imm                      = encode auicgp_raw                       imm        cd
-- auipcc uses same encoding as auipc, so just use auipc
-- auipcc_raw                         =                                        "imm[31:12] cd[4:0] 0010111"
-- auipcc cd imm                      = encode auipcc_raw                       imm       cd

-- Control Flow
-- CHERIoT lacks jalr_cap (jalr.cap) instr
-- jalr_cap_raw                       =                                        "1111111 01100 cs1[4:0] 000 cd[4:0] 1011011"
-- jalr_cap cd cs1                    = encode jalr_cap_raw                                      cs1          cd
-- CHERIoT lacks cinvoke instr
-- cinvoke_raw                        =                                        "1111110 cs2[4:0] cs1[4:0] 000 00001 1011011"
-- cinvoke cs2 cs1                    = encode cinvoke_raw                              cs2      cs1

-- Assertion
ctestsubset_raw                    =                                        "0100000 cs2[4:0] cs1[4:0] 000 rd[4:0] 1011011"
ctestsubset rd cs1 cs2             = encode ctestsubset_raw                          cs2      cs1          rd
csetequalexact_raw                 =                                        "0100001 cs2[4:0] cs1[4:0] 000 rd[4:0] 1011011"
csetequalexact rd cs1 cs2          = encode csetequalexact_raw                       cs2      cs1          rd

-- Register Clearing
-- CHERIoT lacks clear instr
-- clear_raw                          =                                        "1111111 01101 q[1:0] imm[7:5] 000 imm[4:0] 1011011"
-- clear q imm                        = encode clear_raw                                      q      imm
-- CHERIoT lacks cclear instr
-- cclear_raw                         =                                        "1111111 01110 q[1:0] imm[7:5] 000 imm[4:0] 1011011"
-- cclear q imm                       = encode cclear_raw                                     q      imm
-- CHERIoT lacks fpclear instr
-- fpclear_raw                        =                                        "1111111 10000 q[1:0] imm[7:5] 000 imm[4:0] 1011011"
-- fpclear q imm                      = encode fpclear_raw                                    q      imm

-- Adjusting to Compressed Capability Precision
croundrepresentablelength_raw      =                                        "1111111 01000 rs1[4:0] 000 rd[4:0] 1011011"
croundrepresentablelength rd rs1   = encode croundrepresentablelength_raw                  rs1          rd
crepresentablealignmentmask_raw    =                                        "1111111 01001 rs1[4:0] 000 rd[4:0] 1011011"
crepresentablealignmentmask rd rs1 = encode crepresentablealignmentmask_raw                rs1          rd

-- Memory -- Needs further refinement
-- CHERIoT lacks mem loads w/explicit addr
-- cload_raw                          =                                        "1111101 mop[4:0] cb[4:0] 000 cd[4:0] 1011011"
-- cload cd cb mop                    = encode cload_raw                                mop      cb          cd
-- CHERIoT lacks mem stores w/explicit addr
-- cstore_raw                         =                                        "1111100 rs2[4:0] cs1[4:0] 000 mop[4:0] 1011011"
-- cstore rs2 cs1 mop                 = encode cstore_raw                               rs2      cs1          mop
-- clc formerly known as lq
clc_raw                            =                                        "imm[11:0] cs1[4:0] 011 cd[4:0] 0000011" -- [C]LC in RV32 Xcheri | CLC in CHERIoT
clc cd cs1 imm                     = encode clc_raw                          imm       cs1          cd
-- csc formerly known as sq (note: swapped reg order)
csc_raw                            =                                        "imm[11:5] cs2[4:0] cs1[4:0] 011 imm[4:0] 0100011" -- [C]SC in RV32 Xcheri | CSC in CHERIoT
csc cs2 cs1 imm                    = encode csc_raw                          imm       cs2      cs1
-- CHERIoT lacks lr_q (lr.c/q) atomic instr
-- lr_q_raw                           =                                        "00010 aq[0] rl[0]    00000 rs1[4:0] 011 cd[4:0] 0101111" -- LR.C in RV32 Xcheri
-- lr_q cd rs1 aq rl                  = encode lr_q_raw                               aq    rl             rs1          cd
-- CHERIoT lacks sc_q (sc.c/q) atomic instr
-- sc_q_raw                           =                                        "00011 aq[0] rl[0] cs2[4:0] rs1[4:0] 011 rd[4:0] 0101111" -- SC.C in RV32 Xcheri
-- sc_q rd rs1 cs2 aq rl              = encode sc_q_raw                               aq    rl    cs2      rs1          rd
-- CHERIoT lacks amoswap_q (amoswap.c/q) atomic instr
-- amoswap_q_raw                      =                                        "00001 aq[0] rl[0] cs2[4:0] rs1[4:0] 011 cd[4:0] 0101111" -- AMOSWAP.C in RV32 Xcheri
-- amoswap_q cd rs1 cs2 aq rl         = encode amoswap_q_raw                          aq    rl    cs2      rs1          cd

-- CHERIoT lacks mem loads w/explicit addr
-- | Pretty-print a capability load instruction
-- prettyCLoad :: Integer -> Integer -> Integer -> String
-- prettyCLoad mop rs1 rd =
--   concat [instr, " ", reg rd, ", ", reg rs1, "[0]"]
--     where instr = case mop of 0x00 -> "lb.ddc"
--                               0x01 -> "lh.ddc"
--                               0x02 -> "lw.ddc"
--                               0x03 -> "ld.ddc"
--                               0x04 -> "lbu.ddc"
--                               0x05 -> "lhu.ddc"
--                               0x06 -> "lwu.ddc"
--                               0x07 -> "ldu.ddc"  -- TODO clarify meaning...
--                               0x08 -> "lb.cap"
--                               0x09 -> "lh.cap"
--                               0x0a -> "lw.cap"
--                               0x0b -> "ld.cap"
--                               0x0c -> "lbu.cap"
--                               0x0d -> "lhu.cap"
--                               0x0e -> "lwu.cap"
--                               0x0f -> "ldu.cap"  -- TODO clarify meaning...
--                               0x10 -> "lr.b.ddc"
--                               0x11 -> "lr.h.ddc"
--                               0x12 -> "lr.w.ddc"
--                               0x13 -> "lr.d.ddc"
--                               0x14 -> "lr.q.ddc" -- TODO only valid in rv64
--                               0x15 -> "INVALID"
--                               0x16 -> "INVALID"
--                               0x17 -> "lq.ddc"   -- TODO only valid in rv64
--                               0x18 -> "lr.b.cap"
--                               0x19 -> "lr.h.cap"
--                               0x1a -> "lr.w.cap"
--                               0x1b -> "lr.d.cap"
--                               0x1c -> "lr.q.cap" -- TODO only valid in rv64
--                               0x1d -> "INVALID"
--                               0x1e -> "INVALID"
--                               0x1f -> "lq.cap"   -- TODO only valid in rv64
--                               _    -> "INVALID"

-- CHERIoT lacks mem stores w/explicit addr
-- | Pretty-print a capability store instruction
-- prettyCStore :: Integer -> Integer -> Integer -> String
-- prettyCStore rs2 rs1 mop =
--   concat [instr, " ", reg rs2, ", ", reg rs1, "[0]"]
--     where instr = case mop of 0x00 -> "sb.ddc"
--                               0x01 -> "sh.ddc"
--                               0x02 -> "sw.ddc"
--                               0x03 -> "sd.ddc"
--                               0x04 -> "sq.ddc"   -- TODO only valid in rv64
--                               0x08 -> "sb.cap"
--                               0x09 -> "sh.cap"
--                               0x0a -> "sw.cap"
--                               0x0b -> "sd.cap"
--                               0x0c -> "sq.cap"   -- TODO only valid in rv64
--                               0x10 -> "sc.b.ddc"
--                               0x11 -> "sc.h.ddc"
--                               0x12 -> "sc.w.ddc"
--                               0x13 -> "sc.d.ddc"
--                               0x14 -> "sc.q.ddc" -- TODO only valid in rv64
--                               0x18 -> "sc.b.cap"
--                               0x19 -> "sc.h.cap"
--                               0x1a -> "sc.w.cap"
--                               0x1b -> "sc.d.cap"
--                               0x1c -> "sc.q.cap" -- TODO only valid in rv64
--                               _ -> "INVALID"

-- CHERIoT lacks clear,cclear, and fpclear instructions
-- | Pretty-print a register clear instruction
-- pretty_reg_clear instr imm qt = concat [instr, " ", int qt, ", ", int imm]

-- | Pretty-print a 2 sources instruction
pretty_2src instr src2 src1 = concat [instr, " ", reg src1, ", ", reg src2]

-- | Pretty-print a special capability read/write instruction
pretty_cspecialrw instr idx cs1 cd =
  concat [instr, " ", reg cd, ", ", name_scr idx, ", ", reg cs1]
  where name_scr 0 = "pcc"
        name_scr 1 = "ddc"
        name_scr 4 = "utcc"
        name_scr 5 = "utdc"
        name_scr 6 = "uscratchc"
        name_scr 7 = "uepcc"
        name_scr 12 = "stcc"
        name_scr 13 = "stdc"
        name_scr 14 = "sscratchc"
        name_scr 15 = "sepcc"
        name_scr 28 = "mtcc"
        name_scr 29 = "mtdc"
        name_scr 30 = "mscratchc"
        name_scr 31 = "mepcc"
        name_scr idx = int idx

-- | Dissassembly of CHERI instructions
rv32_xcheri_disass :: [DecodeBranch String]
rv32_xcheri_disass = [ cgetperm_raw                    --> prettyR_2op "cgetperm"
                     , cgettype_raw                    --> prettyR_2op "cgettype"
                     , cgetbase_raw                    --> prettyR_2op "cgetbase"
                     , cgetlen_raw                     --> prettyR_2op "cgetlen"
                     , cgettag_raw                     --> prettyR_2op "cgettag"
                    --  , cgetsealed_raw                  --> prettyR_2op "cgetsealed" -- CHERIoT lacks cgetsealed instr
                    --  , cgetoffset_raw                  --> prettyR_2op "cgetoffset" -- CHERIoT lacks cgetoffset instr
                     , cgetaddr_raw                    --> prettyR_2op "cgetaddr"
                     , cgethigh_raw                    --> prettyR_2op "cgethigh"
                     , cgettop_raw                     --> prettyR_2op "cgettop"
                     , cseal_raw                       --> prettyR "cseal"
                     , cunseal_raw                     --> prettyR "cunseal"
                     , candperm_raw                    --> prettyR "candperm"
                    --  , csetoffset_raw                  --> prettyR "csetoffset" -- CHERIoT lacks csetoffset instr
                     , csetaddr_raw                    --> prettyR "csetaddr"
                     , csethigh_raw                    --> prettyR "csethigh"
                    --  , cincoffset_raw                  --> prettyR "cincoffset" -- CHERIoT replaces cincoffset with cincaddr
                     , cincaddr_raw                    --> prettyR "cincaddr"      -- CHERIoT replaces cincoffset with cincaddr
                     , csetbounds_raw                  --> prettyR "csetbounds"
                     , csetboundsexact_raw             --> prettyR "csetboundsexact"
                    --  , cbuildcap_raw                   --> prettyR "cbuildcap" -- CHERIoT lacks cbuildcap instr
                    --  , ccopytype_raw                   --> prettyR "ccopytype" -- CHERIoT lacks ccopytype instr
                    --  , ccseal_raw                      --> prettyR "ccseal" -- CHERIoT lacks ccseal instr
                    --  , csealentry_raw                  --> prettyR_2op "csealentry" -- CHERIoT lacks csealentry instr
                     , cloadtags_raw                   --> prettyR_2op "cloadtags" -- CHERIoT lacks cloadtags instr, disabled using has_nocloadtags rather than code removal
                     , ccleartag_raw                   --> prettyR_2op "ccleartag"
                    --  , cincoffsetimmediate_raw         --> prettyI "cincoffsetimmediate" -- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
                     , cincaddrimm_raw                 --> prettyI "cincaddrimm"            -- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
                     , csetboundsimmediate_raw         --> prettyI "csetboundsimmediate"
                    --  , ctoptr_raw                      --> prettyR "ctoptr" -- CHERIoT lacks ctoptr instr
                    --  , cfromptr_raw                    --> prettyR "cfromptr" -- CHERIoT lacks cfromptr instr
                     , csub_raw                        --> prettyR "csub"
                     , cspecialrw_raw                  --> pretty_cspecialrw "cspecialrw"
                     , auicgp_raw                      --> prettyU "auicgp"
                    --  , auipcc_raw                      --> prettyU "auipcc" -- auipcc uses same encoding as auipc, so just use auipc
                     , cmove_raw                       --> prettyR_2op "cmove"
                    --  , jalr_cap_raw                       --> prettyR_2op "jalr_cap" -- CHERIoT lacks jalr_cap (jalr.cap) instr
                    --  , cinvoke_raw                     --> pretty_2src "cinvoke" -- CHERIoT lacks cinvoke instr
                     , ctestsubset_raw                 --> prettyR "ctestsubset"
                     , csetequalexact_raw              --> prettyR "csetequalexact"
                    --  , clear_raw                       --> pretty_reg_clear "clear" -- CHERIoT lacks clear instr
                    --  , cclear_raw                      --> pretty_reg_clear "cclear" -- CHERIoT lacks cclear instr
                    --  , fpclear_raw                     --> pretty_reg_clear "fpclear" -- CHERIoT lacks fpclear instr
                     , croundrepresentablelength_raw   --> prettyR_2op "croundrepresentablelength"
                     , crepresentablealignmentmask_raw --> prettyR_2op "crepresentablealignmentmask"
                    --  , cload_raw                       --> prettyCLoad -- CHERIoT lacks mem loads w/explicit addr
                    --  , cstore_raw                      --> prettyCStore -- CHERIoT lacks mem stores w/explicit addr
                    --  , cgetflags_raw                   --> prettyR_2op "cgetflags" -- CHERIoT lacks cgetflags instr
                    --  , csetflags_raw                   --> prettyR "csetflags" -- CHERIoT lacks csetflags instr
                     , csc_raw                         --> prettyS "csc" -- csc formerly known as sq (note: swapped reg order)
                     , clc_raw                         --> prettyL "clc" ] -- clc formerly known as lq
                    --  , lr_q_raw                        --> prettyR_A_1op "lr.q" -- CHERIoT lacks lr_q (lr.c/q) atomic instr
                    --  , sc_q_raw                        --> prettyR_A "sc.q" -- CHERIoT lacks sc_q (sc.c/q) atomic instr

extract_cspecialrw :: Integer -> Integer -> Integer -> ExtractedRegs
extract_cspecialrw idx rs1 rd = (False, Nothing, Just rs1, Just rd, \x y z -> encode cspecialrw_raw idx y z)

extract_cmove :: Integer -> Integer -> ExtractedRegs
extract_cmove rs1 rd = (True, Nothing, Just rs1, Just rd, \x y z -> encode cmove_raw y z)

-- CHERIoT lacks cinvoke instr
-- extract_cinvoke :: Integer -> Integer -> ExtractedRegs
-- extract_cinvoke rs2 rs1 = (False, Just rs2, Just rs1, Just 31, \x y z -> encode cinvoke_raw x y)

-- CHERIoT lacks mem stores w/explicit addr
-- extract_cstore :: Integer -> Integer -> Integer -> ExtractedRegs
-- extract_cstore rs2 rs1 mop = (False, Just rs2, Just rs1, Nothing, \x y z -> encode cstore_raw x y mop)

rv32_xcheri_extract :: [DecodeBranch ExtractedRegs]
rv32_xcheri_extract = [ cgetperm_raw                    --> extract_1op cgetperm_raw
                      , cgettype_raw                    --> extract_1op cgettype_raw
                      , cgetbase_raw                    --> extract_1op cgetbase_raw
                      , cgetlen_raw                     --> extract_1op cgetlen_raw
                      , cgettag_raw                     --> extract_1op cgettag_raw
                      -- , cgetsealed_raw                  --> extract_1op cgetsealed_raw -- CHERIoT lacks cgetsealed instr
                      -- , cgetoffset_raw                  --> extract_1op cgetoffset_raw -- CHERIoT lacks cgetoffset instr
                      -- , cgetflags_raw                   --> extract_1op cgetflags_raw -- CHERIoT lacks cgetflags instr
                      , cgetaddr_raw                    --> extract_1op cgetaddr_raw
                      , cgethigh_raw                    --> extract_1op cgethigh_raw
                      , cgettop_raw                     --> extract_1op cgettop_raw
                      , cseal_raw                       --> extract_2op cseal_raw
                      , cunseal_raw                     --> extract_2op cunseal_raw
                      , candperm_raw                    --> extract_2op candperm_raw
                      -- , csetoffset_raw                  --> extract_2op csetoffset_raw -- CHERIoT lacks csetoffset instr
                      , csetaddr_raw                    --> extract_2op csetaddr_raw
                      , csethigh_raw                    --> extract_2op csethigh_raw
                      -- , cincoffset_raw                  --> extract_2op cincoffset_raw -- CHERIoT replaces cincoffset with cincaddr
                      , cincaddr_raw                    --> extract_2op cincaddr_raw      -- CHERIoT replaces cincoffset with cincaddr
                      , csetbounds_raw                  --> extract_2op csetbounds_raw
                      , csetboundsexact_raw             --> extract_2op csetboundsexact_raw
                      -- , cbuildcap_raw                   --> extract_2op cbuildcap_raw -- CHERIoT lacks cbuildcap instr
                      -- , ccopytype_raw                   --> extract_2op ccopytype_raw -- CHERIoT lacks ccopytype instr
                      -- , ccseal_raw                      --> extract_2op ccseal_raw -- CHERIoT lacks ccseal instr
                      -- , csealentry_raw                  --> extract_1op csealentry_raw -- CHERIoT lacks csealentry instr
                      , cloadtags_raw                   --> extract_1op cloadtags_raw -- CHERIoT lacks cloadtags instr, disabled using has_nocloadtags rather than code removal
                      , ccleartag_raw                   --> extract_1op ccleartag_raw
                      -- , cincoffsetimmediate_raw         --> extract_imm cincoffsetimmediate_raw -- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
                      , cincaddrimm_raw                 --> extract_imm cincaddrimm_raw            -- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
                      , csetboundsimmediate_raw         --> extract_imm csetboundsimmediate_raw
                      -- , ctoptr_raw                      --> extract_2op ctoptr_raw -- CHERIoT lacks ctoptr instr
                      -- , cfromptr_raw                    --> extract_2op cfromptr_raw -- CHERIoT lacks cfromptr instr
                      , csub_raw                        --> extract_2op csub_raw
                      , cspecialrw_raw                  --> extract_cspecialrw
                      , auicgp_raw                      --> extract_uimm auicgp_raw
                      -- , auipcc_raw                      --> extract_uimm auipcc_raw -- auipcc uses same encoding as auipc, so just use auipc
                      , cmove_raw                       --> extract_cmove
                      -- , jalr_cap_raw                    --> extract_1op jalr_cap_raw -- CHERIoT lacks jalr_cap (jalr.cap) instr
                      -- , cinvoke_raw                     --> extract_cinvoke -- CHERIoT lacks cinvoke instr
                      , ctestsubset_raw                 --> extract_2op ctestsubset_raw
                      , csetequalexact_raw              --> extract_2op csetequalexact_raw
--                    , clear_raw                       --> noextract -- TODO -- CHERIoT lacks clear instr
--                    , cclear_raw                       --> noextract -- TODO -- CHERIoT lacks cclear instr
--                    , fpclear_raw                     --> noextract -- TODO -- CHERIoT lacks fpclear instr
                      , croundrepresentablelength_raw   --> extract_1op croundrepresentablelength_raw
                      , crepresentablealignmentmask_raw --> extract_1op crepresentablealignmentmask_raw
                      -- , cload_raw                       --> extract_imm cload_raw -- CHERIoT lacks mem loads w/explicit addr
                      -- , cstore_raw                      --> extract_cstore -- CHERIoT lacks mem stores w/explicit addr
                      -- , csetflags_raw                   --> extract_2op csetflags_raw -- CHERIoT lacks csetflags instr
                      , csc_raw                         --> extract_nodst csc_raw -- csc formerly known as sq (note: swapped reg order)
                      , clc_raw                         --> extract_imm clc_raw -- clc formerly known as lq
                      ]

shrink_cgetperm :: Integer -> Integer -> [Instruction]
shrink_cgetperm cs rd = [addi rd 0 0, addi rd 0 0x7ff]

shrink_cgettype :: Integer -> Integer -> [Instruction]
shrink_cgettype cs rd = [addi rd 0 0, addi rd 0 6, addi rd 0 0xfff]

shrink_cgetbase :: Integer -> Integer -> [Instruction]
shrink_cgetbase cs rd = [addi rd 0 0]

shrink_cgetlen :: Integer -> Integer -> [Instruction]
shrink_cgetlen cs rd = [addi rd 0 0, addi rd 0 0xfff, cgetbase rd cs]

shrink_cgettag :: Integer -> Integer -> [Instruction]
shrink_cgettag cs rd = [addi rd 0 1, addi rd 0 0]

-- CHERIoT lacks cgetsealed instr
-- shrink_cgetsealed :: Integer -> Integer -> [Instruction]
-- shrink_cgetsealed cs rd = [addi rd 0 1, addi rd 0 0, cgettype rd cs]

shrink_cgetoffset :: Integer -> Integer -> [Instruction]
shrink_cgetoffset cs rd = [addi rd 0 0, cgetaddr rd cs]

-- CHERIoT lacks cgetflags instr
-- shrink_cgetflags :: Integer -> Integer -> [Instruction]
-- shrink_cgetflags cs rd = [addi rd 0 0, addi rd 0 1]

shrink_cgetaddr :: Integer -> Integer -> [Instruction]
shrink_cgetaddr cs rd = [addi rd cs 0]

shrink_cgethigh :: Integer -> Integer -> [Instruction]
shrink_cgethigh cs rd = [addi rd cs 0, addi rd cs 0xfff]

-- TODO create shrink_cgettop and add cgettop to shrink_cap (is applicable)

shrink_cap :: Integer -> Integer -> [Instruction]
shrink_cap cs cd = [ecall,
                    cmove cd cs,
                    cgetaddr cd cs,
                    cgethigh cd cs,
                    cgetperm cd cs,
                    cgettype cd cs,
                    cgetbase cd cs,
                    cgetlen cd cs,
                    cgettag cd cs
                    -- cgetoffset cd cs, -- CHERIoT lacks cgetoffset instr
                    -- cgetflags cd cs -- CHERIoT lacks cgetflags instr
                   ]

shrink_capcap :: Integer -> Integer -> Integer -> [Instruction]
shrink_capcap cs2 cs1 cd = (shrink_cap cs2 cd) ++ (shrink_cap cs1 cd)

shrink_capint :: Integer -> Integer -> Integer -> [Instruction]
shrink_capint rs cs cd = shrink_cap cs cd

shrink_capimm :: Integer -> Integer -> Integer -> [Instruction]
shrink_capimm imm cs cd = shrink_cap cs cd ++ [addi cd 0 imm, addi cd cs imm]

shrink_cmove :: Integer -> Integer -> [Instruction]
shrink_cmove cs cd = [cgetaddr cd cs]

-- CHERIoT lacks cinvoke instr
-- shrink_cinvoke :: Integer -> Integer -> [Instruction]
-- shrink_cinvoke cs2 cs1 = shrink_capcap cs2 cs1 31

shrink_ctestsubset cs2 cs1 rd = [addi rd 0 0, addi rd 0 1] ++ shrink_capcap cs2 cs1 rd

-- TODO create shrink_csetequalexact

-- CHERIoT lacks cfromptr instr
-- shrink_cfromptr rs cs cd = [csetoffset cd cs rs] ++ shrink_capint rs cs cd

-- CHERIoT lacks mem loads w/explicit addr
-- shrink_cload :: Integer -> Integer -> Integer -> [Instruction]
-- shrink_cload cb cd mop = [addi 0 0 0];

-- CHERIoT lacks mem stores w/explicit addr
-- shrink_cstore :: Integer -> Integer -> Integer -> [Instruction]
-- shrink_cstore rs2 cs1 mop = [addi 0 0 0];

rv32_xcheri_shrink :: [DecodeBranch [Instruction]]
rv32_xcheri_shrink = [ cgetperm_raw                    --> shrink_cgetperm
                     , cgettype_raw                    --> shrink_cgettype
                     , cgetbase_raw                    --> shrink_cgetbase
                     , cgetlen_raw                     --> shrink_cgetlen
                     , cgettag_raw                     --> shrink_cgettag
                    --  , cgetsealed_raw                  --> shrink_cgetsealed -- CHERIoT lacks cgetsealed instr
                    --  , cgetoffset_raw                  --> shrink_cgetoffset -- CHERIoT lacks cgetoffset instr
                    --  , cgetflags_raw                   --> shrink_cgetflags -- CHERIoT lacks cgetflags instr
                     , cgetaddr_raw                    --> shrink_cgetaddr
                     , cgethigh_raw                    --> shrink_cgethigh
                    --  , cgettop_raw                     --> shrink_cgettop -- TODO
                     , cseal_raw                       --> shrink_capcap
                     , cunseal_raw                     --> shrink_capcap
                     , candperm_raw                    --> shrink_capint
                    --  , csetoffset_raw                  --> shrink_capint -- CHERIoT lacks csetoffset instr
                     , csetaddr_raw                    --> shrink_capint
                     , csethigh_raw                    --> shrink_capint
                    --  , cincoffset_raw                  --> shrink_capint -- CHERIoT replaces cincoffset with cincaddr
                     , cincaddr_raw                    --> shrink_capint    -- CHERIoT replaces cincoffset with cincaddr
                     , csetbounds_raw                  --> shrink_capint
                     , csetboundsexact_raw             --> shrink_capint
                    --  , cbuildcap_raw                   --> shrink_capcap -- CHERIoT lacks cbuildcap instr
                    --  , ccopytype_raw                   --> shrink_capcap -- CHERIoT lacks ccopytype instr
                    --  , ccseal_raw                      --> shrink_capcap -- CHERIoT lacks ccseal instr
                    --  , csealentry_raw                  --> shrink_cap -- CHERIoT lacks csealentry instr
                     , ccleartag_raw                   --> shrink_cap
                    --  , cincoffsetimmediate_raw         --> shrink_capimm -- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
                     , cincaddrimm_raw                 --> shrink_capimm    -- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
                     , csetboundsimmediate_raw         --> shrink_capimm
                    --  , ctoptr_raw                      --> shrink_capcap -- CHERIoT lacks ctoptr instr
                    --  , cfromptr_raw                    --> shrink_cfromptr -- CHERIoT lacks cfromptr instr
                     , csub_raw                        --> shrink_capcap
--                   , cspecialrw_raw                  --> noshrink
                     , auicgp_raw                      --> shrink_uimm
                    --  , auipcc_raw                      --> shrink_uimm -- auipcc uses same encoding as auipc, so just use auipc
                     , cmove_raw                       --> shrink_cmove
--                   , jalr_cap_raw                       --> noshrink -- CHERIoT lacks jalr_cap instr
                    --  , cinvoke_raw                     --> shrink_cinvoke -- CHERIoT lacks cinvoke instr
                     , ctestsubset_raw                 --> shrink_ctestsubset
                    --  , csetequalexact_raw              --> shrink_csetequalexact -- TODO
--                   , clear_raw                       --> noshrink -- CHERIoT lacks clear instr
--                   , cclear_raw                      --> noshrink -- CHERIoT lacks cclear instr
--                   , fpclear_raw                     --> noshrink -- CHERIoT lacks fpclear instr
--                   , croundrepresentablelength_raw   --> noshrink
--                   , crepresentablealignmentmask_raw --> noshrink
                    --  , cload_raw                       --> shrink_cload -- CHERIoT lacks mem loads w/explicit addr
                    --  , cstore_raw                      --> shrink_cstore -- CHERIoT lacks mem stores w/explicit addr
                    --  , csetflags_raw                   --> shrink_capcap -- CHERIoT lacks csetflags instr
--                   , csc_raw                         --> noshrink -- csc formerly known as sq (note: swapped reg order)
--                   , clc_raw                         --> noshrink -- clc formerly known as lq
                     ]

-- | List of cheri inspection instructions
rv32_xcheri_inspection :: Integer -> Integer -> [Instruction]
rv32_xcheri_inspection src dest = [ cgetperm                    dest src
                                  , cgettype                    dest src
                                  , cgetbase                    dest src
                                  , cgetlen                     dest src
                                  , cgettag                     dest src
                                  -- , cgetsealed                  dest src -- CHERIoT lacks cgetsealed instr
                                  -- , cgetoffset                  dest src -- CHERIoT lacks cgetoffset instr
                                  , cgetaddr                    dest src
                                  , cgethigh                    dest src
                                  , cgettop                     dest src
                                  -- , cgetflags                   dest src -- CHERIoT lacks cgetflags instr
                                  , croundrepresentablelength   dest src
                                  , crepresentablealignmentmask dest src]

-- | List of cheri arithmetic instructions
rv32_xcheri_arithmetic :: Integer -> Integer -> Integer -> Integer -> [Instruction]
rv32_xcheri_arithmetic src1 src2 imm dest =
  [ -- csetoffset          dest src1 src2 -- CHERIoT lacks csetoffset instr
    csetaddr            dest src1 src2
  , csethigh            dest src1 src2
  -- , cincoffset          dest src1 src2 -- CHERIoT replaces cincoffset with cincaddr
  , cincaddr            dest src1 src2    -- CHERIoT replaces cincoffset with cincaddr
  , csetbounds          dest src1 src2
  , csetboundsexact     dest src1 src2
  , csetboundsimmediate dest src1      imm
  -- , cincoffsetimmediate dest src1      imm -- CHERIoT replaces cincoffsetimm(ediate) with cincaddrimm
  , cincaddrimm         dest src1      imm
  -- , ctoptr              dest src1 src2 -- CHERIoT lacks ctoptr instr
  -- , cfromptr            dest src1 src2 -- CHERIoT lacks cfromptr instr
  , csub                dest src1 src2
  , ctestsubset         dest src1 src2
  , csetequalexact      dest src1 src2 ]

-- | List of cheri miscellaneous instructions
rv32_xcheri_misc :: Integer -> Integer -> Integer -> Integer -> Integer -> [Instruction]
rv32_xcheri_misc src1 src2 srcScr imm dest =
  [ cseal       dest src1 src2
  , cunseal     dest src1 src2
  , candperm    dest src1 src2
  -- , cbuildcap   dest src1 src2 -- CHERIoT lacks cbuildcap instr
  -- , csetflags   dest src1 src2 -- CHERIoT lacks csetflags instr
  -- , ccopytype   dest src1 src2 -- CHERIoT lacks ccopytype instr
  -- , ccseal      dest src1 src2 -- CHERIoT lacks ccseal instr
  -- , csealentry  dest src1 -- CHERIoT lacks csealentry instr
  , ccleartag   dest src1
  , cmove       dest src1
  , cspecialrw  dest srcScr src1
  , auicgp      dest imm ]

-- | List of cheri control instructions
-- rv32_xcheri_control :: Integer -> Integer -> Integer -> [Instruction]
-- rv32_xcheri_control src1 src2 dest = [ jalr_cap dest src1 ] -- CHERIoT lacks jalr_cap (jalr.cap) instr
                                    --  , cinvoke  src2 src1 ] -- CHERIoT lacks cinvoke instr

-- | List of cheri memory instructions
rv32_xcheri_mem :: ArchDesc -> Integer -> Integer -> Integer -> Integer -> Integer -> [Instruction]
rv32_xcheri_mem    arch srcAddr srcData imm mop dest =
  [ -- cload  dest    srcAddr         mop -- CHERIoT lacks mem loads w/explicit addr
  -- , cstore         srcData srcAddr mop -- CHERIoT lacks mem stores w/explicit addr
  --, ld     dest srcAddr dest        imm
  --, sd          srcAddr srcData     imm
  --, clc    dest srcAddr dest        imm -- clc formerly known as lq
  --, csc    srcData srcAddr          imm -- csc formerly known as sq (note: swapped reg order)
  ]
  ++ [cloadtags dest srcAddr | not $ has_nocloadtags arch] -- CHERIoT lacks cloadtags instr, disabled using has_nocloadtags rather than code removal

-- | List of cheri memory instructions
rv32_a_xcheri :: Integer -> Integer -> Integer -> [Instruction]
rv32_a_xcheri      srcAddr srcData dest =
  [ -- cload  dest    srcAddr         0x10 -- lr.b.ddc -- CHERIoT lacks mem loads w/explicit addr
  -- , cload  dest    srcAddr         0x11 -- lr.h.ddc -- CHERIoT lacks mem loads w/explicit addr
  -- , cload  dest    srcAddr         0x12 -- lr.w.ddc -- CHERIoT lacks mem loads w/explicit addr
  -- , cload  dest    srcAddr         0x13 -- lr.d.ddc -- CHERIoT lacks mem loads w/explicit addr
  -- , cload  dest    srcAddr         0x14 -- lr.q.ddc -- CHERIoT lacks mem loads w/explicit addr
  -- , cload  dest    srcAddr         0x18 -- lr.b.cap -- CHERIoT lacks mem loads w/explicit addr
  -- , cload  dest    srcAddr         0x19 -- lr.h.cap -- CHERIoT lacks mem loads w/explicit addr
  -- , cload  dest    srcAddr         0x1a -- lr.w.cap -- CHERIoT lacks mem loads w/explicit addr
  -- , cload  dest    srcAddr         0x1b -- lr.d.cap -- CHERIoT lacks mem loads w/explicit addr
  -- , cload  dest    srcAddr         0x1c -- lr.q.cap -- CHERIoT lacks mem loads w/explicit addr
  -- , cstore         srcData srcAddr 0x10 -- sc.b.ddc -- CHERIoT lacks mem stores w/explicit addr
  -- , cstore         srcData srcAddr 0x11 -- sc.h.ddc -- CHERIoT lacks mem stores w/explicit addr
  -- , cstore         srcData srcAddr 0x12 -- sc.w.ddc -- CHERIoT lacks mem stores w/explicit addr
  -- , cstore         srcData srcAddr 0x13 -- sc.d.ddc -- CHERIoT lacks mem stores w/explicit addr
  -- , cstore         srcData srcAddr 0x14 -- sc.q.ddc -- CHERIoT lacks mem stores w/explicit addr
  -- , cstore         srcData srcAddr 0x18 -- sc.b.cap -- CHERIoT lacks mem stores w/explicit addr
  -- , cstore         srcData srcAddr 0x19 -- sc.h.cap -- CHERIoT lacks mem stores w/explicit addr
  -- , cstore         srcData srcAddr 0x1a -- sc.w.cap -- CHERIoT lacks mem stores w/explicit addr
  -- , cstore         srcData srcAddr 0x1b -- sc.d.cap -- CHERIoT lacks mem stores w/explicit addr
  -- , cstore         srcData srcAddr 0x1c -- sc.q.cap -- CHERIoT lacks mem stores w/explicit addr
  ]

-- | List of cheri instructions
rv32_xcheri :: ArchDesc -> Integer -> Integer -> Integer -> Integer -> Integer -> Integer -> [Instruction]
rv32_xcheri arch src1 src2 srcScr imm mop dest =
     rv32_xcheri_inspection src1 dest
  ++ rv32_xcheri_arithmetic src1 src2 imm dest
  ++ rv32_xcheri_misc src1 src2 srcScr imm dest
  -- ++ rv32_xcheri_control src1 src2 -- CHERIoT lacks cinvoke and jalr_cap (jalr.cap) instr
  ++ rv32_xcheri_mem arch src1 src2 imm mop dest
