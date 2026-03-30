#include <iostream>
#include <vector>
#include <sys/stat.h>

#include "Controller.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

using namespace std;

void check_arguments(int argc, char *argv[]);
vector<double> read_image(const char *filename);

int context_version;
int verbose;
string input_filename;
Controller controller;

int main(int argc, char *argv[])
{
    check_arguments(argc, argv);

    if(context_version==-1){
        cout << "You did not give me anything about the context version!" << endl;
        exit(1);
    }
    if(context_version>0){
        switch (context_version) {
            case 1:
                controller.generateContext(16, 52, 48, 2, 3, 3, 59, true);
                break;
            case 2:
                controller.generateContext(16, 50, 46, 3, 4, 4, 200, true);
                break;
            case 3:
                controller.generateContext(16, 50, 46, 3, 5, 4, 119, true);
                break;
            case 4:
                controller.generateContext(16, 48, 44, 2, 4, 4, 59, true);
                break;
            default:
                controller.generateContext(true);//default context，按照ResNet20的参数设置
                break;
            }

        controller.generateBootstrappingAndRotationKeys({1, -1, 32, -32, -1024},
                                                            16384,
                                                            true,
                                                            "rotations-layer1.bin");
    
        controller.clear_context();
        controller.loadContext(false);
        controller.generateRotationKeys({1, 2, 4, 8, 64-16, -(1024 - 256), (1024 - 256) * 32, -8192},
                                          true,
                                          "rotations-layer2-downsample.bin");
        

        controller.clear_context();
        controller.loadContext(false);
        controller.generateBootstrappingAndRotationKeys({1, -1, 16, -16, -256},
                                          8192,
                                          true,
                                          "rotations-layer2.bin");
    
        controller.clear_context();
        controller.loadContext(false);
        controller.generateRotationKeys({1, 2, 4, 32 - 8, -(256 - 64), (256 - 64) * 64, -4096},
                                          true,
                                          "rotations-layer3-downsample.bin");
        
        controller.clear_context();
        controller.loadContext(false);
        controller.generateBootstrappingAndRotationKeys({1, -1, 8, -8, -64},
                                          4096,
                                          true,
                                          "rotations-layer3.bin");
        
        controller.clear_context();
        controller.loadContext(false);
        controller.generateRotationKeys({1, 2, 4, 8, 16, 32, -15, 64, 128, 256, 512, 1024, 2048}, true, "rotations-finallayer.bin");

        controller.clear_context();
        controller.loadContext(false);

        cout << "Context created correctly." << endl;
        exit(0);

    } else {
        controller.loadContext(verbose > 1);
    }

    Ctxt firstLayer, resLayer1, resLayer2, resLayer3, finalRes;

    vector<double> input_image = read_image(input_filename.c_str());

    Ctxt c = controller.Encrypt(controller.Encode(input_image, controller.circuitDepth - 4 - relu_depth[controller.relu_degree]));

    controller.load_bootstrapping_and_rotation_keys("rotations-layer1.bin", 16384);

    auto start =begin_time();

    firstLayer = controller.initLayer(c);
    if (verbose>1) controller.print(firstLayer, 16384, "Initial layer: ");

    auto startLayer = begin_time();
    resLayer1 = controller.layer1(firstLayer);
    Serial::SerializeToFile("../checkpoints/layer1.bin", resLayer1, SerType::BINARY);
    if (verbose>1) controller.print(resLayer1, 16384, "Layer 1: ");
    if (verbose>0) print_duration(startLayer, "Layer 1 took:");

    auto startLayer2 = begin_time();
    resLayer2 = controller.layer2(resLayer1);
    Serial::SerializeToFile("../checkpoints/layer2.bin", resLayer2, SerType::BINARY);
    if (verbose>1) controller.print(resLayer2, 8192, "Layer 2: ");
    if (verbose>0) print_duration(startLayer2, "Layer 2 took:");

    auto startLayer3 = begin_time();
    resLayer3 = controller.layer3(resLayer2);
    Serial::SerializeToFile("../checkpoints/layer3.bin", resLayer3, SerType::BINARY);
    if (verbose>1) controller.print(resLayer3, 4096, "Layer 3: ");
    if (verbose>0) print_duration(startLayer3, "Layer 3 took:");

    Serial::DeserializeFromFile("../checkpoints/layer3.bin", resLayer3, SerType::BINARY);
    finalRes = controller.classificationLayer(resLayer3,input_filename,verbose);
    Serial::SerializeToFile("../checkpoints/finalres.bin", finalRes, SerType::BINARY);


    if (verbose > 0) print_duration_yellow(start, "The evaluation of the whole circuit took: ");
}

void check_arguments(int argc, char *argv[])
{
    context_version=-1;

    for (int i = 1; i < argc; ++i) {
        //I first check the "verbose" command
        if (string(argv[i]) == "verbose") {
            if (i + 1 < argc) { // Verifica se c'è un argomento successivo a "input"
                verbose = atoi(argv[i + 1]);
            }
        }
    }

    for(int i=1;i<argc;i++){
        if(string(argv[i])=="load_keys"){
            if(i+1<argc){
                controller.controllerFolder="keys_"+string(argv[i+1]);
                context_version=0;
            }
            else{
                cout << "You need to specify the context version after \"load_keys\"!" << endl;
                exit(1);
            }
        }
        else if(string(argv[i])=="generate_keys"){
            if(i+1<argc){
                context_version=stoi(string(argv[i+1]));
                if (context_version==1||context_version==2||context_version==3||context_version==4)
                {            
                    controller.controllerFolder="keys_"+to_string(context_version);
                }
                else{exit(1);}
                
                struct stat sb;
                if (stat(("../keys_" + to_string(context_version)).c_str(), &sb) == 0) {
                    cerr << "The keys folder \"" << "keys_"+to_string(context_version) << "\" already exists, I will abort.";
                    exit(1);
                }
                else {
                    mkdir(("../keys_"+to_string(context_version)).c_str(), 0777);
                }
            }
            else{
                cout << "You need to specify the context version after \"generate_keys\"!" << endl;
                exit(1);
            }
        }
        else if(string(argv[i])=="input"){
            if(i+1<argc)
                input_filename="../"+string(argv[i+1]);               
        }
        else{
            cout << "Cannot figure out the argument " << argv[i] << endl;
            exit(1);
        }
    }
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
        //Channel R
        imageVector.push_back(static_cast<double>(image_data[3 * i]) / 255.0f);
    }
    for (int i = 0; i < width * height; ++i) {
        //Channel G
        imageVector.push_back(static_cast<double>(image_data[1 + 3 * i]) / 255.0f);
    }
    for (int i = 0; i < width * height; ++i) {
        //Channel B
        imageVector.push_back(static_cast<double>(image_data[2 + 3 * i]) / 255.0f);
    }

    stbi_image_free(image_data);

    return imageVector;
}