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

    std::vector<unsigned char> encode_as_ppm(const std::vector<double>& pixels, int index) {
        // 像素总数 32*32*3 = 3072
        const int width = 32, height = 32, maxval = 255;

        // 构造 PPM 头部
        std::ostringstream header;
        header << "P6\n" << width << " " << height << "\n" << maxval << "\n";
        std::string head_str = header.str();

        // 准备最终数据：头部 + 二进制像素
        std::vector<unsigned char> ppm;
        ppm.reserve(head_str.size() + 3072);
        ppm.insert(ppm.end(), head_str.begin(), head_str.end());

        // 将通道分离的数据重新交织为 RGB 顺序，并转为 0~255
        for (int i = 0; i < width * height; ++i) {
            unsigned char r = static_cast<unsigned char>(pixels[i] * 255.0 + 0.5);
            unsigned char g = static_cast<unsigned char>(pixels[1024 + i] * 255.0 + 0.5);
            unsigned char b = static_cast<unsigned char>(pixels[2048 + i] * 255.0 + 0.5);
            ppm.push_back(r);
            ppm.push_back(g);
            ppm.push_back(b);
        }

        const std::string dir = "../data/PPM";
        static bool dir_created = false;
        if (!dir_created) {
            // 创建目录（若不存在），忽略已存在的错误
            if (mkdir(dir.c_str(), 0777) != 0 && errno != EEXIST) {
                std::cerr << "Failed to create directory " << dir << std::endl;
            }
            dir_created = true;
        }

        char fname[64];
        snprintf(fname, sizeof(fname), "img_%04d.ppm", index);  // 例如 img_0001.ppm
        std::string filepath = dir + "/" + fname;

        std::ofstream ofs(filepath, std::ios::binary);
        if (ofs.is_open()) {
            ofs.write(reinterpret_cast<const char*>(ppm.data()), ppm.size());
            ofs.close();
        } else {
            std::cerr << "Cannot write PPM to " << filepath << std::endl;
        }

        return ppm;
    }

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

void handleCipherForBatch(const httplib::Request& req, httplib::Response& res) {
    std::cout << "cipher_for_batch" << std::endl;
    res.set_header("Content-Type", "text/event-stream");
    res.set_header("Cache-Control", "no-cache");
    res.set_header("Connection", "keep-alive");
    res.set_header("X-Accel-Buffering", "no");

    res.set_chunked_content_provider(
        "text/event-stream", 
        [&req](size_t offset, httplib::DataSink &sink) -> bool {
            if (offset > 0) {
                sink.done();
                return false;
            }

            if (!is_fhe_initialized() && fhe_init() != 0) {
                std::string err = "event: error\ndata: {\"error\":\"FHE not initialized\"}\n\n";
                sink.write(err.data(), err.size());
                sink.done();
                return false;
            }

            int test_num = 100;
            if (req.has_param("num")) {
                try { test_num = std::stoi(req.get_param_value("num")); } catch (...) {}
            }

            auto test_images = utils::read_cifar10_batch(
                "../data/cifar-10-batches-bin/test_batch.bin", test_num);
            int total = test_images.size();

            nlohmann::json start_msg = {{"total", total}};
            std::string start_event = "event: start\ndata: " + start_msg.dump() + "\n\n";
            if (!sink.write(start_event.data(), start_event.size())) {
                sink.done(); return false;
            }

            int correct_cnt = 0;
            long peak_mem = 0;
            double sum_time = 0.0;

            for (int i = 0; i < total; ++i) {
                auto img_data = test_images[i];
                int true_label = static_cast<int>(img_data.back());
                img_data.pop_back();   // img_data 现在只有 3072 个像素值

                // 将像素编码为 PPM 图像文件内容
                std::vector<unsigned char> ppm_bytes = encode_as_ppm(img_data, i+1);

                auto t_start = std::chrono::steady_clock::now();
                // 调用单张图像接口（内部会写临时文件 -> stbi_load -> executeResNet20）
                int pred = fhe_classify_image(ppm_bytes.data(), ppm_bytes.size());
                auto t_end = std::chrono::steady_clock::now();

                double ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();
                bool ok = (pred == true_label);
                if (ok) ++correct_cnt;
                sum_time += ms;

                long cur_mem = utils::get_current_maxrss(); 
                if (cur_mem > peak_mem) peak_mem = cur_mem;

                nlohmann::json item = {
                    {"index", i+1},
                    {"true_label", true_label},
                    {"prediction", pred},
                    {"correct", ok},
                    {"time_ms", ms},
                    {"memory_kb", cur_mem}
                };
                std::string result_event = "event: result\ndata: " + item.dump() + "\n\n";

                // 发送该条结果；若失败（如客户端断开）则终止
                if (!sink.write(result_event.data(), result_event.size())) {
                    sink.done();
                    return false;
                }
                // 发送成功，继续下一张
                std::cout << "cipher_for_batch: image" << i << " done" << std::endl;
            }

            // 发送 done 事件并正常结束
            nlohmann::json summary = {
                {"total", total},
                {"correct", correct_cnt},
                {"accuracy", total > 0 ? (100.0 * correct_cnt / total) : 0.0},
                {"average_time_ms", total > 0 ? (sum_time / total) : 0.0},
                {"peak_memory_kb", peak_mem}
            };
            std::string done_event = "event: done\ndata: " + summary.dump() + "\n\n";
            sink.write(done_event.data(), done_event.size());
            sink.done();
            return false;  
        },
        [](bool success) {}
    );
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