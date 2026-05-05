#ifndef HANDLER_H
#define HANDLER_H

#include <string>

std::string handlePlainForOne(const std::string& imageData, const std::string& originalFilename);
std::string handlePlainForBatch();
std::string handleCipherForOne(const std::string& imageData, const std::string& filename,int true_label=-1);
std::string handleCipherForBatch();

std::string handleUpdateKeys();

#endif