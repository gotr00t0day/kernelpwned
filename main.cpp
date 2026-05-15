#include "modules/kernelpwn.h"
#include <iostream>

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

void banner() {
    std::cout << WHITE << BOLD << R"(
         _nnnn_                      
        dGGGGMMb     ,"""""""""""""""""""".
       @p~qp~~qMb    | Linux Kenel Pwned! |
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
                                                                        
)" << RESET;
    std::cout << CYAN << "                  Linux Kernel Vulnerability Scanner v1.3" << RESET << std::endl;
    std::cout << YELLOW << "                      Author: c0d3Ninja" << RESET << std::endl;
    std::cout << BOLD << "========================================================================" << RESET << std::endl;
    std::cout << "\n\n";
}

int main() {
    banner();
    checkVuln();
    return 0;
}
