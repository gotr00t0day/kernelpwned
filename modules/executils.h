#pragma once
#include <string>
#include <vector>

int commandExists(const std::string& cmd);
std::string execCommand(const std::string& cmd);
void runCommand(const std::vector<const char*>& args);