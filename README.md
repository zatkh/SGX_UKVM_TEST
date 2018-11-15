# SGX-UKVM_TEST

build: 
>> install SGX linux SDK,driver,PSW

driver: https://github.com/intel/linux-sgx-driver

sdk: https://github.com/intel/linux-sgx

>> make (make SGX_MODE=HW by defult)
if don't have sgx enabled system >> make SGX_MODE=SIM

>> make -C solo5_sgx

run tests:

./sgx_ukvm test*.ukvm 
