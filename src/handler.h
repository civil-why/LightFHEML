#ifndef HANDLER_H
#define HANDLER_H

#include <string>

std::string handlePlainForOne(const std::string& imageData, const std::string& originalFilename);
std::string handlePlainForBatch();
std::string handleCipherForOne(const std::string& imageData, const std::string& filename,int true_label=-1);
// std::string handleCipherForBatch();
void handleCipherForBatch(const httplib::Request& req, httplib::Response& res);//改为流式，根据后端处理结果发送事件


std::string handleUpdateKeys();

#endif