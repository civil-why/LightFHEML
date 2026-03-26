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
    }

    controller.generateBootstrappingAndRotationKeys({1, -1, 32, -32, -1024},
                                                            16384,
                                                            true,
                                                            "rotations-layer1.bin");
        
    

}

void check_arguments(int argc, char *argv[])
{
    context_version=-1;
    for(int i=0;i<argc;i++){
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