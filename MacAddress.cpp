// get_mac_address.cpp
// g++ -o get_mac_address get_mac_address.cpp



#include <string>
#include <regex>
#include <fstream>
#include <streambuf>
#include <iostream>

#define MAC_ADDR_LEN 6

bool get_mac_address(const std::string& if_name, uint8_t *mac_addr_buf) {
    std::string mac_addr;
    std::ifstream iface("/sys/class/net/" + if_name + "/address");
    std::string str((std::istreambuf_iterator<char>(iface)), std::istreambuf_iterator<char>());
    if (str.length() > 0) {
        std::string hex = regex_replace(str, std::regex(":"), "");
        uint64_t result = stoull(hex, 0, 16);
        for (int i = 0; i < MAC_ADDR_LEN; i++) {
            mac_addr_buf[i] = (uint8_t) ((result & ((uint64_t) 0xFF << (i * 8))) >> (i * 8));
        }

        return true;
    }

    return false;
}

int main(int argc, char *argv[]) {
    if (argv[1]) {
        std::cout << "Interface Name: " << argv[1] << "\n";
        uint8_t mac_addr[MAC_ADDR_LEN];
        if (get_mac_address(std::string(argv[1]), mac_addr)) {
            char temp[MAC_ADDR_LEN * 3 + 1] = {0,};
            snprintf(temp, MAC_ADDR_LEN * 3, "%02X:%02X:%02X:%02X:%02X:%02X", 
                mac_addr[5], mac_addr[4], mac_addr[3], mac_addr[2], mac_addr[1], mac_addr[0]);

            std::cout << "MAC Address: " << std::string(temp) << "\n";
        }
    }

    return 0;
}
