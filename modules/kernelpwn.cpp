/*
         _nnnn_                      
        dGGGGMMb     ,"""""""""""""".
       @p~qp~~qMb    | Linux Rules! |
       M|@||@) M|   _;..............'
       @,----.JM| -'
      JS^\__/  qKL
     dZP        qKRb
    dZP          qKKb
   fZP            SMMb
   HZM            MMMM
   FqM            MMMM
 __| ".        |\dS"qML
 |    `.       | `' \Zq
_)      \.___.,|     .'
\____   )MMMMMM|   .'
     `-'       `--' 

    kernelpwn - Kernel Exploit Suggester
    This tool is used to check if the kernel is vulnerable to a known exploit.
    Author: c0d3Ninja
    Version: 1.2
*/


#include "../modules/executils.h"
#include <cstddef>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <list>

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"
#define UNDERLINE "\033[4m"

struct kernelVuln {
    std::string cve;
    std::string name;
    std::vector<std::string> affected_versions;
    std::string exploit_url;
};

std::string getDistroName() {
    std::ifstream file("/etc/os-release");
    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind("NAME=", 0) == 0) {
            std::string name = line.substr(5);
            if (!name.empty() && name.front() == '"' && name.back() == '"')
                name = name.substr(1, name.size() - 2);
            return name;
        }
    }
    return "Unknown";
}

std::string getUbuntuVersion() {
    std::ifstream file("/etc/os-release");
    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind("VERSION_ID=", 0) == 0) {
            std::string version = line.substr(11);
            return version;
        }
    }
    return "Unknown"; 
}

std::vector<std::string> DirtyCow()  {
    std::vector<std::string> versions;
    versions.reserve(108);
    for (int major = 4; major >= 2; major--) {
        for (int minor = 8; minor >= 0; minor--) {
            for (int patch = 3; patch >= 0; patch--) {
                versions.push_back(std::to_string(major) + "." + 
                                   std::to_string(minor) + "." + 
                                   std::to_string(patch));
            }
        }
    }
    return versions;
}

std::vector<std::string> DirtyPipe() {
    std::vector<std::string> versions;
    versions.reserve(650);
    for (int minor = 8; minor <= 10; minor++) {
        int maxPatch = (minor == 10) ? 101 : 255;
        for (int patch = 0; patch <= maxPatch; patch++) {
            versions.push_back("5." + std::to_string(minor) + "." + std::to_string(patch));
        }
    }
    for (int patch = 0; patch <= 24; patch++) {
        versions.push_back("5.15." + std::to_string(patch));
    }
    for (int patch = 0; patch <= 10; patch++) {
        versions.push_back("5.16." + std::to_string(patch));
    }
    return versions;
}

std::vector<std::string> DirtyFragVersions() {
    // Dirty Frag is gated on esp4/esp6/rxrpc exposure, not a simple uname list.
    return {};
}

std::string DirtyFragModuleScan() {
    std::vector<std::string> loadedModules;
    std::list<std::string> loadableModules;
    std::string cmd = "lsmod | grep -E '^(esp4|esp6|rxrpc)' 2>/dev/null";
    std::string results = execCommand(cmd.c_str());
    size_t pos = results.find(" ");
    if (pos != std::string::npos) {
        results = results.substr(0, pos);
    }
    if (!results.empty() && results.back() == '\n') {
        results.pop_back();
    }
    loadedModules.emplace_back(results);

    auto loadablemodules = [](const std::string& module){
        std::string cmd = "modprobe -n -v " + module;
        std::string results = execCommand(cmd.c_str());
        return results;
    };
    std::string esp4 = "esp4";
    std::string esp6 = "esp6";
    std::string rxrpc = "rxrpc";
    std::string esp4Module = loadablemodules(esp4);
    std::string esp6Module = loadablemodules(esp6);
    std::string rxrpcModule = loadablemodules(rxrpc);
    if (!esp4Module.empty() && esp4Module.rfind("insmod", 0) == 0) {
        loadableModules.push_back("esp4");
    }
    if (!esp6Module.empty() && esp6Module.rfind("insmod", 0) == 0) {
        loadableModules.push_back("esp6");
    }
    if (!rxrpcModule.empty() && rxrpcModule.rfind("insmod", 0) == 0) {
        loadableModules.push_back("rxrpc");
    }
    if (!loadedModules.empty()) {
        for (const auto& loadedM : loadedModules) {
            return "Loaded Module: " + loadedM;
        }
    }
    if (!loadableModules.empty()) {
        for (const auto& loadableM : loadableModules) {
            return "Loadable Module: " + loadableM;
        }
    }
    return "";
}

std::vector<std::string> GameOverLay() {
    std::vector<std::string> versions = {"6.2.0", "5.19.0", "5.4.0"};
    return versions;
}

std::vector<std::string> CVE_2024_1086() {
    std::vector<std::string> versions;
    versions.reserve(595);
    for (int minor = 15; minor <= 19; minor++) {
        for (int patch = 0; patch <= 10; patch++) {
            versions.push_back("3." + std::to_string(minor) + "." + std::to_string(patch));
        }
    }
    for (int minor = 0; minor <= 20; minor++) {
        for (int patch = 0; patch <= 10; patch++) {
            versions.push_back("4." + std::to_string(minor) + "." + std::to_string(patch));
        }
    }
    for (int minor = 0; minor <= 19; minor++) {
        for (int patch = 0; patch <= 10; patch++) {
            versions.push_back("5." + std::to_string(minor) + "." + std::to_string(patch));
        }
    }
    for (int minor = 0; minor <= 7; minor++) {
        for (int patch = 0; patch <= 10; patch++) {
            versions.push_back("6." + std::to_string(minor) + "." + std::to_string(patch));
        }
    }
    versions.push_back("6.8");
    return versions;
}

std::vector<std::string> CopyFailVersions() {
    // CVE-2026-31431 — affected from ~4.14 up to 6.18.21 / 6.19.11 / 7.0-rc1
    std::vector<std::string> versions;
    // 4.14 – 4.19
    for (int minor = 14; minor <= 19; minor++)
        for (int patch = 0; patch <= 255; patch++)
            versions.emplace_back("4." + std::to_string(minor) + "." + std::to_string(patch));
    // 5.0 – 5.19
    for (int minor = 0; minor <= 19; minor++)
        for (int patch = 0; patch <= 255; patch++)
            versions.emplace_back("5." + std::to_string(minor) + "." + std::to_string(patch));
    // 6.0 – 6.17
    for (int minor = 0; minor <= 17; minor++)
        for (int patch = 0; patch <= 255; patch++)
            versions.emplace_back("6." + std::to_string(minor) + "." + std::to_string(patch));
    // 6.18.0 – 6.18.21
    for (int patch = 0; patch <= 21; patch++)
        versions.emplace_back("6.18." + std::to_string(patch));
    // 6.19.0 – 6.19.11
    for (int patch = 0; patch <= 11; patch++)
        versions.emplace_back("6.19." + std::to_string(patch));
    // 7.0-rc1
    versions.emplace_back("7.0-rc1");
    return versions;
}

bool checkAlgif_Aead() {
    std::string cmd = "lsmod | grep algif_aead";
    std::string results = execCommand(cmd.c_str());
    bool output;
    if (!results.empty()) {
        output = true;
    } else {
        output = false;
    }
    return output;
}

bool checkAuthencesn() {
    std::string cmd = "grep -r authencesn /proc/crypto 2>/dev/null";
    std::string results = execCommand(cmd.c_str());
    bool output;
    if (!results.empty()) {
        output = true;
    } else {
        output = false;
    }
    return output;
}

std::vector<kernelVuln> kernelVulns = {
    {"CVE-2016-5195", "Dirty COW", DirtyCow(), "https://github.com/firefart/dirtycow"},
    {"CVE-2022-0847", "Dirty Pipe", DirtyPipe(), "https://github.com/Al1ex/CVE-2022-0847"},
    {"CVE-2023-32629", "GameOver(lay)", GameOverLay(), "https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629"},
    {"CVE-2024-1086", "CVE-2024-1086", CVE_2024_1086(), "https://github.com/Notselwyn/CVE-2024-1086"},
    {"CVE-2026-31431", "Copy Fail", CopyFailVersions(), "https://github.com/theori-io/copy-fail-CVE-2026-31431"},
    {"CVE-2026-43284", "Dirty Frag", DirtyFragVersions(), "https://github.com/V4bel/dirtyfrag"}
};

void checkVuln() {
    std::string cmd = "uname -r";
    std::string uname = execCommand(cmd.c_str());
    size_t pos = uname.find('+');
    if (pos != std::string::npos) {
        uname = uname.substr(0, pos);
    }
    if (!uname.empty() && uname.back() == '\n') {
        uname.pop_back();
    }
    std::cout << "Kernel version: " << YELLOW << uname << RESET << "\n\n\n";

    for (const auto& vuln : kernelVulns) {
        if (vuln.cve == "CVE-2026-43284") {
            std::string dirtyResults = DirtyFragModuleScan();
            if (!dirtyResults.empty()) {
                std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
                std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
                std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
                std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
                if (dirtyResults.rfind("Loadable", 0) == 0) {
                    std::cout << YELLOW << "Found Loadable Modules!" << "\n";
                } else if (dirtyResults.rfind("Loaded", 0) == 0) {
                    std::cout << YELLOW << "Found Loaded Modules!" << "\n";
                }
            }
            continue;
        }
        if (std::find(vuln.affected_versions.begin(), vuln.affected_versions.end(), uname) != vuln.affected_versions.end()) {
            if (vuln.cve == "CVE-2026-31431") {
                if (checkAlgif_Aead() && checkAuthencesn()) {
                    std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
                    std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
                    std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
                    std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
                }
                continue;
            }
            if (vuln.cve == "CVE-2023-32629") {
                if (getDistroName() == "Ubuntu") {
                    std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
                    std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
                    std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
                    std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
                } else {
                    std::cout << vuln.name << " (" << vuln.cve << ")" << YELLOW << " NOT VULNERABLE" << RESET << "\n\n";
                }
                continue;
            }
            std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
            std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
            std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
            std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
        } else {
            std::cout << vuln.name << " (" << vuln.cve << ")" << YELLOW << " NOT VULNERABLE" << RESET << "\n\n";
        }
    }
}
