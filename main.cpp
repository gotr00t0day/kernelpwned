#include "modules/kernelpwn.h"
#include <iostream>

void banner() {
    std::cout << RED << BOLD << R"(
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
