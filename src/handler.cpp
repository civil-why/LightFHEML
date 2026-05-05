// handler.cpp
#include "handler.h"
#include "httplib.h"
#include "json.hpp"

#include "core.h"
#include "Utils.h"
#include <fstream>
#include <cstdio>
#include <chrono>
#include <random>
#include <algorithm>
#include <array>
#include <memory>
#include <unistd.h>      
#include <sys/wait.h>   
#include <sys/resource.h>

namespace {

    std::string extract_json(const std::string& output) {
        const std::string START = "JSON_RESULT_START";
        const std::string END   = "JSON_RESULT_END";
        size_t start = output.find(START);
        size_t end   = output.find(END);
        if (start != std::string::npos && end != std::string::npos) {
            start += START.length();
            while (start < output.size() && (output[start] == '\n' || output[start] == '\r')) ++start;
            std::string json = output.substr(start, end - start);
            size_t first = json.find_first_not_of(" \t\n\r");
            size_t last  = json.find_last_not_of(" \t\n\r");
            if (first != std::string::npos && last != std::string::npos) {
                json = json.substr(first, last - first + 1);
            }
            return json;
        }
        return R"({"error": "Failed to parse Python output"})";
    }

    std::pair<std::string, int> run_command(const std::string& cmd) {
        std::array<char, 128> buffer;
        std::string result;
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("popen() failed");
        }
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            result += buffer.data();
        }
        int retcode = pclose(pipe);
        int exit_code = 0;
        if (WIFEXITED(retcode)) {
            exit_code = WEXITSTATUS(retcode);
        } else {
            exit_code = -1;
        }
        return {result, exit_code};
    }

    class TempFile {
    public:
        explicit TempFile() {
            std::string pattern = "/tmp/fhe_plain_XXXXXX";
            std::vector<char> tmp(pattern.begin(), pattern.end());
            tmp.push_back('\0');
            int fd = mkstemp(tmp.data());
            if (fd == -1) {
                std::cerr << "mkstemp failed on pattern: " << pattern << std::endl;
                std::cerr << "errno: " << errno << " (" << strerror(errno) << ")" << std::endl;
                throw std::runtime_error("Failed to create temporary file");
            }
            path_ = std::string(tmp.data());
            close(fd);
        }

        ~TempFile() {
            if (!path_.empty()) {
                unlink(path_.c_str());
            }
        }

        TempFile(const TempFile&) = delete;
        TempFile& operator=(const TempFile&) = delete;

        TempFile(TempFile&& other) noexcept : path_(std::move(other.path_)) {
            other.path_.clear();
        }
        TempFile& operator=(TempFile&& other) noexcept {
            if (this != &other) {
                if (!path_.empty()) unlink(path_.c_str());
                path_ = std::move(other.path_);
                other.path_.clear();
            }
            return *this;
        }

        const std::string& path() const { return path_; }

    private:
        std::string path_;
    };

    void write_temp_file(const TempFile& tf, const std::string& data) {
        std::ofstream ofs(tf.path(), std::ios::binary);
        if (!ofs) {
            throw std::runtime_error("Cannot write to temp file");
        }
        ofs.write(data.data(), data.size());
        if (!ofs) {
            throw std::runtime_error("Write error");
        }
    }

} 

std::string handlePlainForOne(const std::string& imageData, const std::string& originalFilename) {
    try {
        TempFile tmpFile;
        write_temp_file(tmpFile, imageData);
        std::string cmd = "python3 ../src/plain/plain.py \"" + tmpFile.path() + "\" 2>&1";
        auto [output, exit_code] = run_command(cmd);
        if (exit_code != 0) {
            nlohmann::json err;
            err["error"] = "Python script failed with exit code " + std::to_string(exit_code);
            err["details"] = output;
            return err.dump();
        }
        return extract_json(output);
    } catch (const std::exception& e) {
        nlohmann::json err;
        err["error"] = e.what();
        return err.dump();
    }
}

std::string handlePlainForBatch() {
    std::string cmd = "python3 ../src/plain/plain_efficiency.py 2>&1";
        auto [output, exit_code] = run_command(cmd);
        if (exit_code != 0) {
            nlohmann::json err;
            err["error"] = "Python script failed with exit code " + std::to_string(exit_code);
            err["details"] = output;
            return err.dump();
        }
        return extract_json(output);
}

std::string handleCipherForOne(const std::string& imageData, const std::string& filename, int true_label) {
    nlohmann::json resp;
    
    auto start = std::chrono::steady_clock::now();
    long start_mem = utils::get_current_maxrss();   
    
    // 调用 FHE 分类
    int label = fhe_classify_image(reinterpret_cast<const unsigned char*>(imageData.data()), imageData.size());
    
    // 计算耗时
    auto end = std::chrono::steady_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    long end_mem = utils::get_current_maxrss();
    long mem_delta = (end_mem > start_mem) ? (end_mem - start_mem) : 0;
    
    if (label >= 0) {
        resp["prediction"] = label;
        resp["time_ms"] = elapsed_ms;
        resp["memory_delta_kb"] = mem_delta;
        if (true_label != -1) {
            resp["correct"] = (label == true_label);
        }
    } else {
        resp["error"] = "FHE classification failed";
        resp["time_ms"] = elapsed_ms;
        resp["memory_delta_kb"] = mem_delta;
    }
    
    return resp.dump();
}

std::string handleCipherForBatch() {
    return fhe_run_test(100);  
}

std::string handleUpdateKeys() {
    nlohmann::json resp;
    int ret = fhe_generate_keys(4);  
    if (ret == 0) {
        resp["status"] = "success";
        resp["message"] = "Keys generated successfully.";
    } else {
        resp["status"] = "failed";
        resp["detail"] = "Key generation failed. Check logs for details.";
    }
    return resp.dump();
}