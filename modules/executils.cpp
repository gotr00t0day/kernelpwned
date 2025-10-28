#include "../modules/executils.h"
#include <cstdlib>
#include <array>
#include <cstdio>
#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/wait.h>

void runCommand(const std::vector<const char*>& args) {
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return;
    }

    if (pid == 0) {
        execvp(args[0], (char* const*)args.data());
        perror("execvp");
        _exit(1);
    } else {
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
        } else if (WIFEXITED(status)) {
            std::cout << args[0] << " exited with code "
                      << WEXITSTATUS(status) << "\n";
        }
    }
}


int commandExists(const std::string& cmd) {
    std::string check = "command -v " + cmd + " >/dev/null 2>&1";
    return std::system(check.c_str()) == 0;
}

std::string execCommand(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "ERROR";

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe);
    return result;
}