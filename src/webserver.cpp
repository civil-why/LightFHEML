#include "httplib.h"
#include "handler.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.set_mount_point("/", "../web");

    svr.Post("/plain_for_one", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.form.has_file("image")) {
            res.status = 400;
            res.set_content(R"({"error": "No image uploaded"})", "application/json");
            return;
        }
        auto file = req.form.get_file("image");
        std::string result = handlePlainForOne(file.content, file.filename);
        res.set_content(result, "application/json");
    });

    svr.Post("/plain_for_batch", [](const httplib::Request& req, httplib::Response& res) {
        std::string result = handlePlainForBatch();
        res.set_content(result, "application/json");
    });

    svr.Post("/cipher_for_one", [](const httplib::Request& req, httplib::Response& res) {
        std::cout<<"cipher_for_one"<<std::endl;
        if (!req.form.has_file("image")) {
            res.status = 400;
            res.set_content(R"({"error": "No image uploaded"})", "application/json");
            return;
        }
        auto file = req.form.get_file("image");
        int true_label = -1;
        if (req.has_param("true_label")) {
            try {
                true_label = std::stoi(req.get_param_value("true_label"));
            } catch (...) { /* ignore */ }
        }
        std::string result = handleCipherForOne(file.content, file.filename, true_label);
        res.set_content(result, "application/json");
    });

    svr.Post("/cipher_for_batch", handleCipherForBatch);

    svr.Get("/update_keys", [](const httplib::Request&, httplib::Response& res) {
        std::string result = handleUpdateKeys();
        res.set_content(result, "application/json");
    });

    std::cout << "Server running at http://localhost:8080" << std::endl;
    svr.listen("0.0.0.0", 8080);
    return 0;
}