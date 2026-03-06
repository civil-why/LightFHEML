#ifndef LightFHEML_TOOLS_H
#define LightFHEML_TOOLS_H

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

    static map<int,string> find_class ={
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
    }}


#endif