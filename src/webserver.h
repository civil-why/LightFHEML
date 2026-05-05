#ifndef WEBSERVER_H
#define WEBSERVER_H


// 生成唯一临时文件名（可指定后缀）
std::string temp_filename(const std::string& suffix = ".png") {
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::random_device rd;
    return "/tmp/fhe_" + std::to_string(now) + "_" + std::to_string(rd()) + suffix;
}

#endif // WEBSERVER_H
