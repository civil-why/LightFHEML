#include <iostream>
#include <sys/stat.h>

#include "FHEController.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

void check_arguments(int argc, char *argv[]);
vector<double> read_image(const char *filename);
