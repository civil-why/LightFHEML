//core.h
#ifndef CORE_H
#define CORE_H

#include <vector>
#include <string>

int fhe_init(void);
int fhe_classify_image(const unsigned char* img_data, size_t data_len);
void fhe_set_verbose(int level);
std::string fhe_run_test(int test_num);

int fhe_generate_keys(int contextType);  
int fhe_load_keys(int key_num);           
int fhe_test_context(void);               

#endif