/*
         _nnnn_                      
        dGGGGMMb     ,"""""""""""""""""""".
       @p~qp~~qMb    | Linux Kernel Pwned! |
       M|@||@) M|   _;....................'
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


    kernelpwn - Linux Kernel Vulnerability Scanner
    This tool is used to check if the kernel is vulnerable to a known exploit.
    Author: c0d3Ninja
    Version: 1.8
*/


#include "../modules/executils.h"
#include "../modules/trimmer.h"
#include <cstddef>
#include <string>
#include <sys/stat.h>
#include <vector>
#include <iostream>
#include <algorithm>
#include <sstream>
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

std::vector<std::string> Fragnesia() {
    std::string cmd = "grep CONFIG_INET_ESPINTCP /boot/config-$(uname -r) 2>/dev/null";
    std::string results = execCommand(cmd.c_str());
    if (!results.empty() && results.back() == '\n')
        results.pop_back();

    if (results.find("=y") != std::string::npos || results.find("=m") != std::string::npos)
        return {results};

    return {};
}

std::vector<std::string> Fragnesia2() {
    std::string results = DirtyFragModuleScan();
    if (!results.empty())
        return {results};
    return {};
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

static bool kernelAtLeast56(const std::string& uname) {
    unsigned major = 0, minor = 0, patch = 0;
    if (std::sscanf(uname.c_str(), "%u.%u.%u", &major, &minor, &patch) < 2)
        return false;
    return major > 5 || (major == 5 && minor >= 6);
}

static std::string normalizeUname(std::string uname) {
    size_t pos = uname.find('+');
    if (pos != std::string::npos)
        uname = uname.substr(0, pos);
    pos = uname.find('-');
    if (pos != std::string::npos && uname.find('.') != std::string::npos) {
        unsigned major = 0, minor = 0, patch = 0;
        if (std::sscanf(uname.c_str(), "%u.%u.%u", &major, &minor, &patch) >= 2)
            uname = std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
    }
    if (!uname.empty() && uname.back() == '\n')
        uname.pop_back();
    return uname;
}

static bool kernelInCve202623111Range(const std::string& rawUname) {
    const std::string uname = normalizeUname(rawUname);

    if (uname.find("6.19-rc") != std::string::npos)
        return true;

    unsigned major = 0, minor = 0, patch = 0;
    if (std::sscanf(uname.c_str(), "%u.%u.%u", &major, &minor, &patch) < 2)
        return false;

    if (major >= 7)
        return false;

    if (major == 4) {
        if (minor < 19)
            return false;
        if (minor == 19)
            return patch >= 316;
        return false;
    }

    if (major == 5) {
        if (minor == 4)
            return patch >= 262;
        if (minor == 10)
            return patch >= 188;
        if (minor == 15)
            return patch >= 121 && patch < 200;
        return false;
    }

    if (major == 6) {
        if (minor == 0 || minor == 2)
            return false;
        if (minor == 1)
            return patch >= 36 && patch < 163;
        if (minor == 3)
            return patch >= 10;
        if (minor == 4 || minor == 5)
            return true;
        if (minor == 6)
            return patch < 124;
        if (minor >= 7 && minor <= 11)
            return true;
        if (minor == 12)
            return patch < 70;
        if (minor >= 13 && minor <= 17)
            return true;
        if (minor == 18)
            return patch < 10;
        if (minor == 19)
            return false;
        return false;
    }

    return false;
}

static bool kernelInCve202643503Range(const std::string& rawUname) {
    const std::string uname = normalizeUname(rawUname);

    if (uname.find("7.1-rc") != std::string::npos) {
        unsigned rc = 0;
        if (std::sscanf(uname.c_str(), "7.1-rc%u", &rc) == 1)
            return rc >= 1 && rc <= 4;
        return false;
    }

    unsigned major = 0, minor = 0, patch = 0;
    const int parsed = std::sscanf(uname.c_str(), "%u.%u.%u", &major, &minor, &patch);
    if (parsed < 2)
        return false;

    if (major < 3 || (major == 3 && minor < 9))
        return false;
    if (major >= 8)
        return false;

    if (major == 7) {
        if (minor == 0)
            return parsed < 3 || patch < 10;
        return false;
    }

    if (major == 6) {
        if (minor == 0)
            return true;
        if (minor == 1)
            return parsed < 3 || patch < 174;
        if (minor >= 2 && minor <= 5)
            return true;
        if (minor == 6)
            return parsed < 3 || patch < 141;
        if (minor >= 7 && minor <= 11)
            return true;
        if (minor == 12)
            return parsed < 3 || patch < 91;
        if (minor >= 13 && minor <= 17)
            return true;
        if (minor == 18)
            return parsed < 3 || patch < 33;
        if (minor == 19)
            return true;
        return false;
    }

    if (major == 5) {
        if (minor < 10)
            return true;
        if (minor == 10)
            return parsed < 3 || patch < 257;
        if (minor >= 11 && minor <= 14)
            return true;
        if (minor == 15)
            return parsed < 3 || patch < 208;
        return true;
    }

    return true;
}

static bool espModulesReachable() {
    auto loadable = [](const std::string& module) {
        std::string cmd = "modprobe -n -v " + module;
        std::string results = execCommand(cmd.c_str());
        return !results.empty() && results.rfind("insmod", 0) == 0;
    };
    if (!trim(execCommand("lsmod | grep -E '^(esp4|esp6)' 2>/dev/null")).empty())
        return true;
    return loadable("esp4") || loadable("esp6");
}

auto OneCharacterVuln() {
    std::string uname = trim(execCommand("uname -r"));
    std::vector<std::string> vulnerability;
    bool checkConfigNfTables;
    bool nftInstalled;
    bool unprivUserNamespace;
    std::string confignftablesCmd = trim(execCommand("grep CONFIG_NF_TABLES /boot/config-$(uname -r)"));
    if (!confignftablesCmd.empty()) {
        std::string line;
        std::istringstream iss(confignftablesCmd);
        while(std::getline(iss, line)) {
            auto pos = line.find("=");
            if (pos == std::string::npos)
                continue;
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            if (value == "y" || value == "m") {
                checkConfigNfTables = true;
            }
        }
    }
    std::string nftCmd = trim(execCommand("command -v nft"));
    std::string userNamespacesCmd = trim(execCommand("unshare -U -r true 2>/dev/null && echo userns_ok"));
    if (!nftCmd.empty()) {
        nftInstalled = true;
    }
    if (userNamespacesCmd == "userns_ok") {
        unprivUserNamespace = true;
    }
    if (kernelInCve202623111Range(uname) && checkConfigNfTables && nftInstalled && unprivUserNamespace) {
        vulnerability.emplace_back("Vulnerable");
    }
    return vulnerability;
}

 auto DirtyDecrypt() {
    std::string cmd = "grep CONFIG_RXGK /boot/config-$(uname -r) 2>/dev/null";
    std::string results = trim(execCommand(cmd.c_str()));
    std::vector<std::string> vulnerable;
    if (!results.empty()) {
        std::string line;
        std::istringstream iss(results);
        while(getline(iss, line)) {
            if (line.rfind("#", 0) == 0) {
                std::string variable = line.substr(13);
                if (variable.find("is not set")) {
                    vulnerable.emplace_back("No");
                }
            }
            if (line.rfind("CONFIG_RXGK=", 0) == 0) {
                std::string config = line.substr(11);
                if (config.find("y") || config.find("m")) {
                    auto loadablemodules = [](const std::string& module){
                        std::string cmd = "modprobe -n -v " + module;
                        std::string results = execCommand(cmd.c_str());
                        return results;
                    };
                    std::string rxrpc = "rxrpc";
                    std::string rxrpcModule = loadablemodules(rxrpc);
                    if (!rxrpcModule.empty() && rxrpcModule.rfind("insmod", 0) == 0) {
                        vulnerable.emplace_back("Yes");
                    }
                }
            }
        }
    }
    return vulnerable;
}

auto DirtyClone() {
    std::vector<std::string> result;
    std::string uname = trim(execCommand("uname -r"));
    bool kernelVuln = kernelInCve202643503Range(uname);
    bool usernsNetns = trim(execCommand("unshare -Urn true 2>/dev/null && echo userns_netns_ok")) == "userns_netns_ok";
    bool espReachable = espModulesReachable();
    bool nftInstalled = !trim(execCommand("command -v nft")).empty();

    if (kernelVuln && usernsNetns && espReachable && nftInstalled)
        result.emplace_back("Vulnerable");
    return result;
}

static bool ptraceScopeExploitable() {
    std::ifstream f("/proc/sys/kernel/yama/ptrace_scope");
    int scope = -1;
    if (!(f >> scope))
        return false;
    return scope <= 1;
}

static bool hasPrivilegedSuidTarget() {
    auto hasSuid = [](const std::string& path) {
        struct stat st{};
        if (stat(path.c_str(), &st) != 0)
            return false;
        return (st.st_mode & S_ISUID) != 0;
    };
    auto hasSuidOrSgid = [](const std::string& path) {
        struct stat st{};
        if (stat(path.c_str(), &st) != 0)
            return false;
        return (st.st_mode & (S_ISUID | S_ISGID)) != 0;
    };
    return hasSuid("/usr/lib/openssh/ssh-keysign") ||
           hasSuidOrSgid("/usr/bin/chage");
}

std::vector<std::string> sshKeySignPwn() {
    std::string uname = execCommand("uname -r");
    size_t pos = uname.find('+');
    if (pos != std::string::npos)
        uname = uname.substr(0, pos);
    if (!uname.empty() && uname.back() == '\n')
        uname.pop_back();

    if (kernelAtLeast56(uname) && ptraceScopeExploitable() && hasPrivilegedSuidTarget())
        return {uname};

    return {};
}

std::vector<kernelVuln> kernelVulns = {
    {"CVE-2016-5195", "Dirty COW", DirtyCow(), "https://github.com/firefart/dirtycow"},
    {"CVE-2022-0847", "Dirty Pipe", DirtyPipe(), "https://github.com/Al1ex/CVE-2022-0847"},
    {"CVE-2023-32629", "GameOver(lay)", GameOverLay(), "https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629"},
    {"CVE-2024-1086", "CVE-2024-1086", CVE_2024_1086(), "https://github.com/Notselwyn/CVE-2024-1086"},
    {"CVE-2026-46300", "Fragnesia", Fragnesia(), "https://github.com/v12-security/pocs/tree/main/fragnesia"},
    {"CVE-2026-31431", "Copy Fail", CopyFailVersions(), "https://github.com/theori-io/copy-fail-CVE-2026-31431"},
    {"CVE-2026-43284", "Dirty Frag", DirtyFragVersions(), "https://github.com/V4bel/dirtyfrag"},
    {"CVE-2026-46300-2", "Fragnesia2", Fragnesia2(), "https://github.com/v12-security/pocs/tree/main/fragnesia-5db89c99566fc"},
    {"CVE-2026-46333", "SSH Key Sign Pwn", sshKeySignPwn(), "https://github.com/0xdeadbeefnetwork/ssh-keysign-pwn/"},
    {"CVE-2026-23111", "One Character Vunlnerability", OneCharacterVuln(), "https://github.com/jordanpotti/CVE-2026-23111"},
    {"CVE-2026-39364", "Dirty Decrypt", DirtyDecrypt(), "https://github.com/xynet/Dirty-Decrypt"},
    {"CVE-2026-43503", "DirtyClone", {}, "https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/"}
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
            }
            continue;
        } 
        if (vuln.cve == "CVE-2026-39364") {
            const auto result = DirtyDecrypt();
            if (!result.empty() && result[0] == "Yes") {
                std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
                std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
                std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
                std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
            } else {
                std::cout << vuln.name << " (" << vuln.cve << ")" << YELLOW << " NOT VULNERABLE" << RESET << "\n\n";
            }
            continue;
        }
        if (vuln.cve == "CVE-2026-43503") {
            const auto result = DirtyClone();
            if (!result.empty() && result[0] == "Vulnerable") {
                std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
                std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
                std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
                std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
            } else {
                std::cout << vuln.name << " (" << vuln.cve << ")" << YELLOW << " NOT VULNERABLE" << RESET << "\n\n";
            }
            continue;
        }
        if (vuln.cve == "CVE-2026-23111") {
            const auto result = OneCharacterVuln();
            if (!result.empty() && result[0] == "Vulnerable") {
                std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
                std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
                std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
                std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
            } else {
                std::cout << vuln.name << " (" << vuln.cve << ")" << YELLOW << " NOT VULNERABLE" << RESET << "\n\n";
            }
            continue;
        }
        if (vuln.cve == "CVE-2026-46300") {
            if (!Fragnesia().empty()) {
                std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
                std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
                std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
                std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
            } else {
                std::cout << vuln.name << " (" << vuln.cve << ")" << YELLOW << " NOT VULNERABLE" << RESET << "\n\n";
            }
            continue;
        } 
        if (vuln.cve == "CVE-2026-46300-2") {
            std::vector<std::string> fragnesia2Results = Fragnesia2();
            if (!fragnesia2Results.empty()) {
                std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
                std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
                std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
                std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
            } else {
                std::cout << vuln.name << " (" << vuln.cve << ")" << YELLOW << " NOT VULNERABLE" << RESET << "\n\n";
            }
            continue;
        }
        if (vuln.cve == "CVE-2026-46333") {
            if (!vuln.affected_versions.empty()) {
                std::cout << vuln.name << " (" << vuln.cve << ")" << RED << " VULNERABLE!" << RESET << "\n\n";
                std::cout << "Name: " << RED << vuln.name << RESET << "\n\n";
                std::cout << "CVE: " << RED << vuln.cve << RESET << "\n\n";
                std::cout << "PoC: " << RED << vuln.exploit_url << RESET << "\n\n";
            } else {
                std::cout << vuln.name << " (" << vuln.cve << ")" << YELLOW << " NOT VULNERABLE" << RESET << "\n\n";
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


