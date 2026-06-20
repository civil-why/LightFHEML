#include <iostream>
#include <sys/stat.h>
#include <fstream>
#include <cstdint>
#include <sys/resource.h>   
#include <fcntl.h>  
#include <unistd.h>

#include "FHEController.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include "json.hpp"

#define GREEN_TEXT "\033[1;32m"
#define RED_TEXT "\033[1;31m"
#define RESET_COLOR "\033[0m"


void check_arguments(int argc, char *argv[]);
vector<double> read_image(const char *filename);

int executeResNet20(vector<double>& input_image);

Ctxt initial_layer(const Ctxt& in);
Ctxt layer1(const Ctxt& in);
Ctxt layer2(const Ctxt& in);
Ctxt layer3(const Ctxt& in);
Ctxt final_layer(const Ctxt& in);

FHEController controller;

// static int generate_context=-1;
static string input_filename;
static int verbose=1;
// static bool test = false;
static bool plain = false;
static bool test_mode=false;
// static int test_num=100;

static bool g_initialized = false;
bool is_fhe_initialized() { return g_initialized; }
void set_fhe_initialized(bool val) { g_initialized = val; }

int fhe_init() ;
void fhe_set_verbose(int level) {
    verbose = level;
}

std::string fhe_run_test(int test_num) {
    
    if (!g_initialized && fhe_init() != 0) {
        nlohmann::json err = {{"error", "FHE not initialized"}};
        return err.dump();
    }

    auto test_images = utils::read_cifar10_batch("../data/cifar-10-batches-bin/test_batch.bin", test_num);
    int total = test_images.size();
    int correct = 0;
    std::vector<double> times;
    std::vector<bool> corrects;
    
    auto overall_start = std::chrono::steady_clock::now();
    long peak_memory = 0;
    
    for (int idx = 0; idx < total; ++idx) {
        auto img_data = test_images[idx];
        int true_label = static_cast<int>(img_data.back());
        img_data.pop_back();
        
        auto start = std::chrono::steady_clock::now();
        int pred = executeResNet20(img_data);
        auto end = std::chrono::steady_clock::now();
        
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(elapsed_ms);
        bool ok = (pred == true_label);
        corrects.push_back(ok);
        if (ok) ++correct;
        
        long cur_mem = get_current_maxrss();  
        if (cur_mem > peak_memory) peak_memory = cur_mem;
    }
    
    auto overall_end = std::chrono::steady_clock::now();
    double total_time_ms = std::chrono::duration<double, std::milli>(overall_end - overall_start).count();
    double avg_time_ms = total_time_ms / total;
    
    nlohmann::json resp;
    resp["total"] = total;
    resp["correct"] = correct;
    resp["accuracy"] = 100.0 * correct / total;
    resp["average_time_ms"] = avg_time_ms;
    resp["peak_memory_kb"] = peak_memory;
    
    nlohmann::json details = nlohmann::json::array();
    for (int i = 0; i < total; ++i) {
        details.push_back({{"correct", corrects[i]}, {"time_ms", times[i]}});
    }
    resp["details"] = details;
    
    return resp.dump();
}

int fhe_classify_image(const unsigned char* img_data, size_t data_len) {
    
    if (!g_initialized && fhe_init() != 0) return -1;

    std::string old_input_filename = input_filename;
    bool old_test_mode = test_mode;
    test_mode = false;

    int result = -1;
    try {
        TempImageFile tempFile(img_data, data_len);
        input_filename = tempFile.path();

        vector<double> img = read_image(input_filename.c_str());
        if (!img.empty()) {
            result = executeResNet20(img);
        }
    } catch (const std::exception& e) {
        std::cerr << "FHE classification error: " << e.what() << std::endl;
        result = -1;
    }

    input_filename = old_input_filename;
    test_mode = old_test_mode;

    return result;
}

int fhe_generate_keys(int contextType) {
    
    std::cout<<"generate keys begin"<<std::endl;
    string folder;
    switch (contextType) {
        case 1: folder = "keys_exp1"; break;
        case 2: folder = "keys_exp2"; break;
        case 3: folder = "keys_exp3"; break;
        case 4: folder = "keys_exp4"; break;
        default: folder = "keys_exp"; break;
    }
    
    struct stat sb;
    if (stat(("../" + folder).c_str(), &sb) == 0) {
        std::cerr << "The keys folder \"" << folder << "\" already exists. Aborting." << std::endl;
        return -1;
    }
    if (mkdir(("../" + folder).c_str(), 0777) != 0) {
        std::cerr << "Failed to create directory: " << strerror(errno) << std::endl;
        return -1;
    }
    controller.parameters_folder = folder;
    if (verbose > 1) std::cout << "Context folder set to: \"" << controller.parameters_folder << "\"." << std::endl;
    
    try {
        switch (contextType) {
            case 1:
                controller.generate_context(16, 52, 48, 2, 3, 3, 59, true);
                break;
            case 2:
                controller.generate_context(16, 50, 46, 3, 4, 4, 200, true);
                break;
            case 3:
                controller.generate_context(16, 50, 46, 3, 5, 4, 119, true);
                break;
            case 4:
                controller.generate_context(16, 48, 44, 2, 4, 4, 59, true);
                break;
            default:
                controller.generate_context(true);
                break;
        }
        
        if (verbose > 1) std::cout << "Basic context built. Now generating bootstrapping and rotations keys..." << std::endl;
        if (verbose > 1) std::cout << "(It may take a while, depending on the machine)" << std::endl;
        
        controller.generate_bootstrapping_and_rotation_keys({1, -1, 32, -32, -1024},
                                                             16384, true, "rotations-layer1.bin");
        if (verbose > 1) std::cout << "1/6 done." << std::endl;
        controller.clear_context(16384);
        controller.load_context(false);
        controller.generate_rotation_keys({1, 2, 4, 8, 64-16, -(1024 - 256), (1024 - 256) * 32, -8192},
                                          true, "rotations-layer2-downsample.bin");
        if (verbose > 1) std::cout << "2/6 done." << std::endl;
        controller.clear_context(0);
        controller.load_context(false);
        controller.generate_bootstrapping_and_rotation_keys({1, -1, 16, -16, -256},
                                                            8192, true, "rotations-layer2.bin");
        if (verbose > 1) std::cout << "3/6 done." << std::endl;
        controller.clear_context(8192);
        controller.load_context(false);
        controller.generate_rotation_keys({1, 2, 4, 32 - 8, -(256 - 64), (256 - 64) * 64, -4096},
                                          true, "rotations-layer3-downsample.bin");
        if (verbose > 1) std::cout << "4/6 done." << std::endl;
        controller.clear_context(0);
        controller.load_context(false);
        controller.generate_bootstrapping_and_rotation_keys({1, -1, 8, -8, -64},
                                                            4096, true, "rotations-layer3.bin");
        if (verbose > 1) std::cout << "5/6 done." << std::endl;
        controller.clear_context(4096);
        controller.load_context(false);
        controller.generate_rotation_keys({1, 2, 4, 8, 16, 32, -15, 64, 128, 256, 512, 1024, 2048},
                                          true, "rotations-finallayer.bin");
        if (verbose > 1) std::cout << "6/6 done!" << std::endl;
        
        controller.clear_context(0);
        controller.load_context(false);
        
        std::cout << "Context created correctly." << std::endl;
        g_initialized = true;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Key generation failed: " << e.what() << std::endl;
        return -1;
    }
}

int fhe_load_keys(int exp_num) {
    
    string folder = "keys_exp";
    if (exp_num >= 1 && exp_num <= 4) {
        folder = "keys_exp" + std::to_string(exp_num);
    } else if (exp_num == 0) {
        folder = "keys_exp"; 
    } else {
        std::cerr << "Invalid keys number. Use 0 (default), 1, 2, 3, or 4." << std::endl;
        return -1;
    }

    struct stat sb;
    if (stat(("../" + folder).c_str(), &sb) != 0) {
        std::cerr << "Keys folder \"" << folder << "\" does not exist. Generate keys first." << std::endl;
        return -1;
    }
    std::cout<<"load keys begin"<<std::endl;
    controller.parameters_folder = folder;
    if (verbose > 1) std::cout << "Loading keys from \"" << folder << "\"." << std::endl;
    
    try {
        controller.load_context(verbose > 1);
        g_initialized = true;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Failed to load keys: " << e.what() << std::endl;
        return -1;
    }
}

int fhe_init() {
    return fhe_load_keys(4);  
}

int fhe_test_context() {
    
    try {
        controller.test_context();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Context test failed: " << e.what() << std::endl;
        return -1;
    }
}

int executeResNet20(vector<double>& input_image) {
    controller.load_context(false);
    cout << "Encrypted ResNet20 classification started." << endl;

    Ctxt firstLayer, resLayer1, resLayer2, resLayer3, finalRes;

    bool print_intermediate_values = false;
    bool print_bootstrap_precision = false;

    if (verbose > 1) {
        print_intermediate_values = true;
        print_bootstrap_precision = true;
    }

    if (input_filename.empty()&&!test_mode) {
        input_filename = "../inputs/luis.png";
        if (verbose >= 0) cout << "You did not set any input, I use " << GREEN_TEXT << "../inputs/luis.png" << RESET_COLOR << "." << endl;
    } else {
        if (verbose >= 0) cout << "I am going to encrypt and classify " << GREEN_TEXT<< input_filename << RESET_COLOR << "." << endl;
    }

    Ctxt in = controller.encrypt(input_image, controller.circuit_depth - 4 - relu_depth[controller.relu_degree]);
    
    controller.load_bootstrapping_and_rotation_keys("rotations-layer1.bin", 16384, verbose > 1);

    if (print_bootstrap_precision){
        controller.bootstrap_precision(controller.encrypt(input_image, controller.circuit_depth - 2));
    }

    

    auto start = start_time();

    firstLayer = initial_layer(in);
    if (print_intermediate_values) controller.print(firstLayer, 16384, "Initial layer: ");
  
    // Layer 1：16通道，每个图像大小为32x32
    auto startLayer = start_time();
    resLayer1 = layer1(firstLayer);
    Serial::SerializeToFile("../checkpoints/layer1.bin", resLayer1, SerType::BINARY);
    if (print_intermediate_values) controller.print(resLayer1, 16384, "Layer 1: ");
    if (verbose > 0) print_duration(startLayer, "Layer 1 took:");

    // Layer 2：32通道，每个图像大小为16x16
    startLayer = start_time();
    Serial::DeserializeFromFile("../checkpoints/layer1.bin", resLayer1, SerType::BINARY);
    resLayer2 = layer2(resLayer1);
    Serial::SerializeToFile("../checkpoints/layer2.bin", resLayer2, SerType::BINARY);
    if (print_intermediate_values) controller.print(resLayer2, 8192, "Layer 2: ");
    if (verbose > 0) print_duration(startLayer, "Layer 2 took:");

    // Layer 3：64通道，每个图像大小为8x8
    startLayer = start_time();
    Serial::DeserializeFromFile("../checkpoints/layer2.bin", resLayer2, SerType::BINARY);
    resLayer3 = layer3(resLayer2);
    Serial::SerializeToFile("../checkpoints/layer3.bin", resLayer3, SerType::BINARY);
    if (print_intermediate_values) controller.print(resLayer3, 4096, "Layer 3: ");
    if (verbose > 0) print_duration(startLayer, "Layer 3 took:");


    Serial::DeserializeFromFile("../checkpoints/layer3.bin", resLayer3, SerType::BINARY);
    finalRes = final_layer(resLayer3);
    Serial::SerializeToFile("../checkpoints/finalres.bin", finalRes, SerType::BINARY);

    if (verbose > 0) print_duration_yellow(start, "The evaluation of the whole circuit took: ");
    
    vector<double> clear_result = controller.decrypt_tovector(finalRes,10);

    auto max_element_iterator = std::max_element(clear_result.begin(), clear_result.end());
    int index_max = distance(clear_result.begin(), max_element_iterator);

    return index_max;
}

Ctxt initial_layer(const Ctxt& in) {
    double scale = 0.90; 

    Ctxt res = controller.convbn_initial(in, scale, verbose > 1);
    res = controller.relu(res, scale, verbose > 1);

    return res;
}

Ctxt final_layer(const Ctxt& in) {
    controller.clear_bootstrapping_and_rotation_keys(4096);
    controller.load_rotation_keys("rotations-finallayer.bin", false);

    controller.num_slots = 4096;

    Ptxt weight = controller.encode(read_fc_weight("../weights/fc.bin"), in->GetLevel(), controller.num_slots);

    Ctxt res = controller.rotsum(in, 64);
    res = controller.mult(res, controller.mask_mod(64, res->GetLevel(), 1.0 / 64.0));

    res = controller.repeat(res, 16);
    res = controller.mult(res, weight);
    res = controller.rotsum_padded(res, 64);

    if (verbose >= 0) {
        cout << "Decrypting the output..." << endl;
        controller.print(res, 10, "Output: ");
    }

    vector<double> clear_result = controller.decrypt_tovector(res, 10);

    auto max_element_iterator = std::max_element(clear_result.begin(), clear_result.end());
    int index_max = distance(clear_result.begin(), max_element_iterator);

    if (verbose >= 0) {
        cout << "The input image is classified as " << YELLOW_TEXT << utils::class_map[index_max] << RESET_COLOR << "" << endl;
        cout << "The index of max element is " << YELLOW_TEXT << index_max << RESET_COLOR << "" << endl;
        if (plain) {
            string command = "python3 ../src/plain/script.py \"" + input_filename + "\"";
            int return_sys = system(command.c_str());
            if (return_sys == 1) {
                cout << "There was an error launching src/plain/script.py. Run it from Python in order to debug it." << endl;
            }
        }
    }


    return res;
}

Ctxt layer3(const Ctxt& in) {
    double scaleSx = 0.63;
    double scaleDx = 0.40;

    bool timing = verbose > 1;

    if (verbose > 1) cout << "---Start: Layer3 - Block 1---" << endl;
    auto start = start_time();
    Ctxt boot_in = controller.bootstrap(in, timing);

    vector<Ctxt> res1sx = controller.convbn3264sx(boot_in, 7, 1, scaleSx, timing); 
    vector<Ctxt> res1dx = controller.convbn3264dx(boot_in, 7, 1, scaleDx, timing); 

    controller.clear_bootstrapping_and_rotation_keys(8192);
    controller.load_rotation_keys("rotations-layer3-downsample.bin", timing);

    Ctxt fullpackSx = controller.downsample256to64(res1sx[0], res1sx[1]);
    Ctxt fullpackDx = controller.downsample256to64(res1dx[0], res1dx[1]);
    res1sx.clear();
    res1dx.clear();

    controller.clear_rotation_keys();
    controller.load_bootstrapping_and_rotation_keys("rotations-layer3.bin", 4096, verbose > 1);

    controller.num_slots = 4096;
    fullpackSx = controller.bootstrap(fullpackSx, timing);

    fullpackSx = controller.relu(fullpackSx, scaleSx, timing);
    fullpackSx = controller.convbn3(fullpackSx, 7, 2, scaleDx, timing);
    Ctxt res1 = controller.add(fullpackSx, fullpackDx);
    res1 = controller.bootstrap(res1, timing);
    res1 = controller.relu(res1, scaleDx, timing);
    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer3 - Block 1---" << endl;

    double scale = 0.57;


    if (verbose > 1) cout << "---Start: Layer3 - Block 2---" << endl;
    start = start_time();
    Ctxt res2;
    res2 = controller.convbn3(res1, 8, 1, scale, timing);
    res2 = controller.bootstrap(res2, timing);
    res2 = controller.relu(res2, scale, timing);

    scale = 0.33;

    res2 = controller.convbn3(res2, 8, 2, scale, timing);
    res2 = controller.add(res2, controller.mult(res1, scale));
    res2 = controller.bootstrap(res2, timing);
    res2 = controller.relu(res2, scale, timing);
    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer3 - Block 2---" << endl;

    scale = 0.69;

    if (verbose > 1) cout << "---Start: Layer3 - Block 3---" << endl;
    start = start_time();
    Ctxt res3;

    res3 = controller.convbn3(res2, 9, 1, scale, timing);
    res3 = controller.bootstrap(res3, timing);
    res3 = controller.relu(res3, scale, timing);

    scale = 0.1;

    res3 = controller.convbn3(res3, 9, 2, scale, timing);
    res3 = controller.add(res3, controller.mult(res2, scale));
    res3 = controller.bootstrap(res3, timing);
    res3 = controller.relu(res3, scale, timing);
    res3 = controller.bootstrap(res3, timing);

    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer3 - Block 3---" << endl;


    return res3;
}

Ctxt layer2(const Ctxt& in) {

    double scaleSx = 0.57;
    double scaleDx = 0.40;

    bool timing = verbose > 1;

    if (verbose > 1) cout << "---Start: Layer2 - Block 1---" << endl;
    auto start = start_time();
    Ctxt boot_in = controller.bootstrap(in, timing);

    vector<Ctxt> res1sx = controller.convbn1632sx(boot_in, 4, 1, scaleSx, timing); //Questo è lento

    vector<Ctxt> res1dx = controller.convbn1632dx(boot_in, 4, 1, scaleDx, timing); //Questo è lento


    controller.clear_bootstrapping_and_rotation_keys(16384);
    controller.load_rotation_keys("rotations-layer2-downsample.bin", timing);

    Ctxt fullpackSx = controller.downsample1024to256(res1sx[0], res1sx[1]);
    Ctxt fullpackDx = controller.downsample1024to256(res1dx[0], res1dx[1]);


    res1sx.clear();
    res1dx.clear();

    controller.clear_rotation_keys();
    controller.load_bootstrapping_and_rotation_keys("rotations-layer2.bin", 8192, verbose > 1);

    controller.num_slots = 8192;
    fullpackSx = controller.bootstrap(fullpackSx, timing);

    fullpackSx = controller.relu(fullpackSx, scaleSx, timing);

    fullpackSx = controller.convbn2(fullpackSx, 4, 2, scaleDx, timing);
    Ctxt res1 = controller.add(fullpackSx, fullpackDx);
    res1 = controller.bootstrap(res1, timing);
    res1 = controller.relu(res1, scaleDx, timing);
    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer2 - Block 1---" << endl;

    double scale = 0.76;

    if (verbose > 1) cout << "---Start: Layer2 - Block 2---" << endl;
    start = start_time();
    Ctxt res2;
    res2 = controller.convbn2(res1, 5, 1, scale, timing);
    res2 = controller.bootstrap(res2, timing);
    res2 = controller.relu(res2, scale, timing);

    scale = 0.37;

    res2 = controller.convbn2(res2, 5, 2, scale, timing);
    res2 = controller.add(res2, controller.mult(res1, scale));
    res2 = controller.bootstrap(res2, timing);
    res2 = controller.relu(res2, scale, timing);
    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer2 - Block 2---" << endl;

    scale = 0.63;

    if (verbose > 1) cout << "---Start: Layer2 - Block 3---" << endl;
    start = start_time();
    Ctxt res3;
    res3 = controller.convbn2(res2, 6, 1, scale, timing);
    res3 = controller.bootstrap(res3, timing);
    res3 = controller.relu(res3, scale, timing);
  
    scale = 0.25;

    res3 = controller.convbn2(res3, 6, 2, scale, timing);
    res3 = controller.add(res3, controller.mult(res2, scale));
    res3 = controller.bootstrap(res3, timing);
    res3 = controller.relu(res3, scale, timing);
    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer2 - Block 3---" << endl;

    return res3;
}

Ctxt layer1(const Ctxt& in) {
    bool timing = verbose > 1;
    double scale = 1.00;


    if (verbose > 1) cout << "---Start: Layer1 - Block 1---" << endl;
    auto start = start_time();
    Ctxt res1;
    res1 = controller.convbn(in, 1, 1, scale, timing);
    res1 = controller.bootstrap(res1, timing);
    res1 = controller.relu(res1, scale, timing);

    scale = 0.52;

    res1 = controller.convbn(res1, 1, 2, scale, timing);
    res1 = controller.add(res1, controller.mult(in, scale));
    res1 = controller.bootstrap(res1, timing);
    res1 = controller.relu(res1, scale, timing);
    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer1 - Block 1---" << endl;

    scale = 0.55;


    if (verbose > 1) cout << "---Start: Layer1 - Block 2---" << endl;
    start = start_time();
    Ctxt res2;
    res2 = controller.convbn(res1, 2, 1, scale, timing);
    res2 = controller.bootstrap(res2, timing);
    res2 = controller.relu(res2, scale, timing);

    scale = 0.36;

    res2 = controller.convbn(res2, 2, 2, scale, timing);
    res2 = controller.add(res2, controller.mult(res1, scale));
    res2 = controller.bootstrap(res2, timing);
    res2 = controller.relu(res2, scale, timing);
    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer1 - Block 2---" << endl;
  
    scale = 0.63;

    if (verbose > 1) cout << "---Start: Layer1 - Block 3---" << endl;
    start = start_time();
    Ctxt res3;
    res3 = controller.convbn(res2, 3, 1, scale, timing);
    res3 = controller.bootstrap(res3, timing);
    res3 = controller.relu(res3, scale, timing);

    scale = 0.42;
  
    res3 = controller.convbn(res3, 3, 2, scale, timing);
    res3 = controller.add(res3, controller.mult(res2, scale));
    res3 = controller.bootstrap(res3, timing);
    res3 = controller.relu(res3, scale, timing);

    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer1 - Block 3---" << endl;

    return res3;
}

vector<double> read_image(const char *filename) {
    int width = 32;
    int height = 32;
    int channels = 3;
    unsigned char* image_data = stbi_load(filename, &width, &height, &channels, 0);

    if (!image_data) {
        cerr << "Could not load the image in " << filename << endl;
        return vector<double>();
    }

    vector<double> imageVector;
    imageVector.reserve(width * height * channels);

    for (int i = 0; i < width * height; ++i) {
        // R通道
        imageVector.push_back(static_cast<double>(image_data[3 * i]) / 255.0f);
    }
    for (int i = 0; i < width * height; ++i) {
        // G通道
        imageVector.push_back(static_cast<double>(image_data[1 + 3 * i]) / 255.0f);
    }
    for (int i = 0; i < width * height; ++i) {
        // B通道
        imageVector.push_back(static_cast<double>(image_data[2 + 3 * i]) / 255.0f);
    }

    stbi_image_free(image_data);

    return imageVector;
}