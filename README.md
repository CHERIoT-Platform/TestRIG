
This is a quick introduction on how to use TestRIG for CHERIoT design verification. The original TestRIG README is [here](https://github.com/CHERIoT-Platform/TestRIG/edit/master/README.orig.md).

## Getting Started
1. Clone this repo and get all submodules.

2. Build the cheriot-sail (RFVI version) simulator.
   - This should generate a executable at riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32
   ```
   cd riscv-implementations
   make rvfi
   ```
     
3. Build/run cheriot-ibex simulation, 
   - Currently we only have a flow using VCS.To build the testbench,
     ```
     cd cheriot-ibex/dv/uvm/core_ibex
     ./testrig_vcs_build.sh
     ```
   - The VCS simulation may either run on a local machine (same machine running TestRIG) or on a remote server. In both cases the VCS simulation will create a socket and listening for the incoming DII packets sent by TestRIG.
     ```
       export RVFI_DII_PORT=6000
       ./vcs_testrig_out/simv -ucli -do ./vcs_testrig.tcl +UVM_TESTNAME=core_ibex_testrig_test -cm line+cond+tgl+fsm+branch+assert +enable_ibex_fcov=1 -cm_dir sim -l run.log
     ```
4. RunTestRIG. Currently it runs simulations on two implementations in parallel and compares the results. In our case implementation A is cheriot-ibex, implementation B is cheriot-sail (golden reference).
   - See TestRIG/run_example
