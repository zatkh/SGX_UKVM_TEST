SECTIONS
{

        .payload64 0 : {
                guest64 = .;
                ukvm_sgx/guest64.img.o
                guest64_end = .;
        }
}
