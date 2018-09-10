# SGX-UKVM_TEST

build: 
>> make (make SGX_MODE=HW by defult)
if don't have sgx enabled system >> make SGX_MODE=SIM

>> make -C solo5_sgx

run tests:

./sgx_ukvm test*.ukvm 