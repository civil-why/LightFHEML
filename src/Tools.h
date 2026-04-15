#ifndef TOOLS_H
#define TOOLS_H

#include <iostream>
#include <map>
#include <openfhe.h>

#define YELLOW_TEXT "\033[1;33m"
#define RESET_COLOR "\033[0m"

using namespace std;
using namespace std::chrono;
using namespace lbcrypto;

namespace tools {
    static inline chrono::time_point<steady_clock, nanoseconds> begin_time() {
        return steady_clock::now();
    }

    static duration<long long,ratio<1,1000>> duration_time;

    static inline void print_duration(chrono::time_point<steady_clock, nanoseconds> start, const string &title) {
        auto ms = duration_cast<milliseconds>(steady_clock::now() - start);

        duration_time += ms;//duration不一定从0开始

        auto secs = duration_cast<seconds>(ms);//秒
        ms -= duration_cast<milliseconds>(secs);
        auto mins = duration_cast<minutes>(secs);//分
        secs -= duration_cast<seconds>(mins);

        if (mins.count() < 1) {
            cout << title << "Time : " << secs.count() << "." << ms.count() << "s" << " ( " << duration_cast<seconds>(duration_time).count() << "s)" << endl;
        } else {
            cout << title << "Time : " << mins.count() << "min" << secs.count() << "." << ms.count() << "s" << " ( " << duration_cast<seconds>(duration_time).count() << "s)" << endl;
        }
    }

    static inline void print_average_duration(chrono::time_point<steady_clock, nanoseconds> start, const string &title, int test_num) {
        auto ms = duration_cast<milliseconds>(steady_clock::now() - start);

        ms/=test_num;

        duration_time += ms;//duration不一定从0开始

        auto secs = duration_cast<seconds>(ms);//秒
        ms -= duration_cast<milliseconds>(secs);
        auto mins = duration_cast<minutes>(secs);//分
        secs -= duration_cast<seconds>(mins);

        if (mins.count() < 1) {
            cout << title << "Average time : " << secs.count() << "." << ms.count() << "s" << " ( " << duration_cast<seconds>(duration_time).count() << "s)" << endl;
        } else {
            cout << title << "Average time : " << mins.count() << "min" << secs.count() << "." << ms.count() << "s" << " ( " << duration_cast<seconds>(duration_time).count() << "s)" << endl;
        }
    }

    static inline void print_duration_yellow(chrono::time_point<steady_clock, nanoseconds> start, const string &title) {
        auto ms = duration_cast<milliseconds>(steady_clock::now() - start);

        duration_time += ms;//duration不一定从0开始

        auto secs = duration_cast<seconds>(ms);//秒
        ms -= duration_cast<milliseconds>(secs);
        auto mins = duration_cast<minutes>(secs);//分
        secs -= duration_cast<seconds>(mins);

       if (mins.count() < 1) {
            cout << title << "Time : " << secs.count() << "." << ms.count() << "s" << " ( " << duration_cast<seconds>(duration_time).count() << "s)" << endl;
        } else {
            cout << title << "Time : " << YELLOW_TEXT << mins.count() << "min" << secs.count() << "." << ms.count() << RESET_COLOR << "s" << " ( " << duration_cast<seconds>(duration_time).count() << "s)" << endl;
        }
    }

    static map<int,string> class_map ={
        {0,"airplane"},
        {1,"automobile"},
        {2,"bird"},
        {3,"cat"},
        {4,"deer"},
        {5,"dog"},
        {6,"frog"},
        {7,"horse"},
        {8,"ship"},
        {9,"truck"}
    };

    static map<int,int> relu_depth ={//切比雪夫近似，在[-1,1]区间上可以减少一个深度
        {5,3},
        {13,4},
        {27,5},
        {59,6},
        {119,7},
        {200,8},
        {247,8},
        {495,9},
        {1007,10},
        {2031,11}
    };

    static inline void write_to_file(string filename, string content) {
        ofstream file;
        file.open (filename);
        file << content.c_str();
        file.close();
    }

    static inline string read_first_line(string filename) {
        string line;
        ifstream myfile (filename);
        if (myfile.is_open()) {
            if (getline(myfile, line)) {
                myfile.close();
                return line;
            } else {
                cerr << "Cannot open " << filename << "." <<endl;
                exit(1);
            }
        } else {
            cerr << "Cannot open " << filename << "." <<endl;
            exit(1);
        }
    }

    static inline vector<double> read_from_file(string filename,double scale = 1.0) {
        vector<double> res;

        ifstream file (filename);
        if (file.is_open()) {

            string row;
            
            while (std::getline(file, row)) {
               
                istringstream stream(row);
                string value;

                while (std::getline(stream, value, ',')) {
                    try {
                        double num = stod(value);
                        res.push_back(num * scale);
                    } catch (const invalid_argument& e) {
                        cerr << "Cannot convert: " << value << endl;
                    }
                }
            }
        } else {
            cerr << "Cannot open " << filename << "." <<endl;
            return res;
        }
        return res;
    }

    static inline vector<double> read_fc_weight () //我不是很来得及改
    {
        vector<double> weight = read_from_file("../weights/fc.bin");
        vector<double> weight_corrected;

        for (int i = 0; i < 64; i++) {
            for (int j = 0; j < 10; j++) {
                weight_corrected.push_back(weight[(10 * i) + j]);
            }
            for (int j = 0; j < 64 - 10; j++) {
                weight_corrected.push_back(0);
            }
        }

        return weight_corrected;
    }

    static inline double compute_approx_error(Plaintext expected, Plaintext bootstrapped) {
        vector<complex<double>> result;
        vector<complex<double>> expectedResult;

        result = bootstrapped->GetCKKSPackedValue();
        expectedResult = expected->GetCKKSPackedValue();


        if (result.size() != expectedResult.size())
            OPENFHE_THROW(config_error, "Cannot compare vectors with different numbers of elements");

        // using the infinity norm
        double maxError = 0;
        for (size_t i = 0; i < result.size(); ++i) {
            double error = std::abs(result[i].real() - expectedResult[i].real());
            if (maxError < error)
                maxError = error;
        }

        return std::abs(std::log2(maxError));
    }

    static inline vector<vector<double>> read_cifar10_batch(string filename, int num_images = 1000) {
        vector<vector<double>> images;
        ifstream file(filename, ios::binary);
        
        if (!file.is_open()) {
            cerr << "Cannot open " << filename << endl;
            exit(1);
        }
        
        for (int i = 0; i < num_images; i++) {
            vector<double> image;
            unsigned char label;
            file.read((char*)&label, 1); // 读取标签
            
            for (int j = 0; j < 3072; j++) {
                unsigned char pixel;
                file.read((char*)&pixel, 1);
                // 归一化到[0,1]并调整通道顺序为R,G,B分开存储
                image.push_back(static_cast<double>(pixel) / 255.0);
            }
            
            image.push_back(static_cast<double>(label));
            images.push_back(image);
        }
        
        file.close();
        return images;
    }
}

#endif