
######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
ENCLAVE_DIR=enclave

CFLAGS = -Wall -Wextra -O2


ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -Wall -std=gnu99 -O2 -g -DUKVM_MODULE_BLK

else
        SGX_COMMON_CFLAGS += -Wall -std=gnu99 -O2 -g -D_FORTIFY_SOURCE=2 -DUKVM_MODULE_BLK

endif

######## ukvm_sgx Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

U_UKVM_Cpp_Files := ukvm_sgx/main.c ukvm_sgx/ukvm_core.c ukvm_sgx/ukvm_elf.c \
					ukvm_sgx/ukvm_hv_kvm.c ukvm_sgx/ukvm_hv_kvm_x86_64.c ukvm_sgx/ukvm_cpu_x86_64.c \
					ukvm_sgx/ukvm_module_blk.c 

U_UKVM_Include_Paths := -Ienclave -I$(SGX_SDK)/include -Iukvm_sgx

U_UKVM_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(U_UKVM_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        U_UKVM_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        U_UKVM_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        U_UKVM_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

U_UKVM_Cpp_Flags := $(U_UKVM_C_Flags) -std=c++11

U_UKVM_Link_Flags := $(SGX_COMMON_CFLAGS) -Lukvm_sgx -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread 


ifneq ($(SGX_MODE), HW)
	U_UKVM_Link_Flags += -lsgx_uae_service_sim
else
	U_UKVM_Link_Flags += -lsgx_uae_service
endif

U_UKVM_Cpp_Objects := $(U_UKVM_Cpp_Files:.c=.o)

IMG_FLAGS := -L./ -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -lsgx_uae_service



U_UKVM_Executable := sgx_ukvm

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files :=  #enclave/t_mem_mgmt.cpp enclave/t_SgxSSL_api.cpp

Enclave_C_Files := enclave/enclave.c enclave/t_io.c enclave/crc32.c enclave/dir.c enclave/disk.c enclave/encoding.c enclave/entry.c enclave/errno.c enclave/file.c enclave/fs.c enclave/header.c enclave/host.c \
				   enclave/memcpy.c enclave/path.c enclave/status.c enclave/table.c enclave/ramdisk.c enclave/time.c \
				   enclave/size.c enclave/stdhost.c enclave/test_bmfs.c

Enclave_Include_Paths := -IInclude -Ienclave -Ienclave/include -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(OPENSSL_PACKAGE)/include -Ienclave/include/bmfs

Common_C_Cpp_Flags := -DOS_ID=1 $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fpic -fstack-protector -fno-builtin-printf -Wformat -Wformat-security 

Enclave_C_Flags := $(Common_C_Cpp_Flags) $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Common_C_Cpp_Flags) $(Enclave_C_Flags) -std=c++03 -nostdinc++
# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=enclave/enclave.lds 

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := enclave/enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: .config_$(Build_Mode)_$(SGX_ARCH) $(U_UKVM_Executable) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(U_UKVM_Executable) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: .config_$(Build_Mode)_$(SGX_ARCH) $(U_UKVM_Executable) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(U_UKVM_Executable)
	@echo "RUN  =>  $(U_UKVM_Executable) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## interfaces Objects ########

ukvm_sgx/enclave_u.c: $(SGX_EDGER8R) enclave/enclave.edl
	@cd ukvm_sgx && $(SGX_EDGER8R) --untrusted ../enclave/enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

ukvm_sgx/enclave_u.o: ukvm_sgx/enclave_u.c
	@$(CC) $(U_UKVM_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

ukvm_sgx/main.o: ukvm_sgx/main.c 
	@$(CC) $(U_UKVM_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

ukvm_sgx/payload.o: ukvm_sgx/payload.ld ukvm_sgx/guest64.img.o
	$(LD) -T $< -o $@ 

ukvm_sgx/guest64.o: ukvm_sgx/guest.c
	$(CC) $(CFLAGS) $(U_UKVM_C_Flags) -m64 -ffreestanding -fno-pie -c -o $@ $^ 

ukvm_sgx/guest64.img: ukvm_sgx/guest64.o
	$(LD) -T ukvm_sgx/guest.ld $^ -o $@ 


ukvm_sgx/%.img.o: ukvm_sgx/%.img
	$(LD) -b binary -r $^ -o $@ 

ukvm_sgx/ukvm_%.o: ukvm_sgx/ukvm_%.c
	@$(CC) $(U_UKVM_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(U_UKVM_Executable): ukvm_sgx/enclave_u.o $(U_UKVM_Cpp_Objects) 
	@$(CXX) $^ -o $@ $(U_UKVM_Link_Flags)
	@echo "LINK =>  $@"

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(U_UKVM_Executable) $(Enclave_Name) $(Signed_Enclave_Name) $(U_UKVM_Cpp_Objects) ukvm_sgx/enclave_u.* $(Enclave_Cpp_Objects) $(Enclave_C_Objects)  enclave/enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## Enclave Objects ########

enclave/enclave_t.c: $(SGX_EDGER8R) enclave/enclave.edl
	@cd enclave && $(SGX_EDGER8R) --trusted ../enclave/enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave/enclave_t.o: enclave/enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/%.o: enclave/%.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/%.o: enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): enclave/enclave_t.o $(Enclave_Cpp_Objects) $(Enclave_C_Objects) 
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f .config_* $(U_UKVM_Executable) $(Enclave_Name) $(Signed_Enclave_Name) $(U_UKVM_Cpp_Objects) ukvm_sgx/enclave_u.* ukvm_sgx/*.o ukvm_sgx/*.img $(Enclave_Cpp_Objects) $(Enclave_C_Objects) enclave/enclave_t.*  
