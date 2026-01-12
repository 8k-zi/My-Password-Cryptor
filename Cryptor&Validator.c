#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif


static const char SERVER_HOST[] = "127.0.0.1"; 

int init_net() {
#ifdef _WIN32
    WSADATA w; return WSAStartup(0x0202, &w) == 0;
#else
    return 1;
#endif
}

int get_flag(const char* pwd, char* flg, size_t sz) {
    SOCKET s;
    struct sockaddr_in a;
    char req[512], res[1024], body[128];
    
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return 0;
    
    a.sin_family = AF_INET;
    a.sin_port = htons(80); 
    inet_pton(AF_INET, SERVER_HOST, &a.sin_addr);
    

    if (connect(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) {
        closesocket(s); return -1;
    }
    
    snprintf(body, sizeof(body), "{\"password\":\"%s\"}", pwd);
    snprintf(req, sizeof(req),
        "POST /verify HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n%s",
        SERVER_HOST, strlen(body), body);
    
    send(s, req, strlen(req), 0);
    
    memset(res, 0, sizeof(res));
    size_t tot = 0;
    while (tot < sizeof(res) - 1) {
        int r = recv(s, res + tot, sizeof(res) - 1 - tot, 0);
        if (r <= 0) break;
        tot += r;
    }
    closesocket(s);
    
    if (strstr(res, "\"success\"")) {
        char* p = strstr(res, "\"flag\"");
        if (p && (p = strstr(p, ":")) && (p = strchr(p, '\"'))) {
            p++;
            char* e = strchr(p, '\"');
            if (e && (size_t)(e-p) < sz) {
                strncpy(flg, p, e-p); flg[e-p] = 0; return 1;
            }
        }
    }
    return (strstr(res, "\"denied\"")) ? -2 : 0;
}

int main() {
    char in[128], f[128];
    init_net();
    
    while (1) {
        printf("Enter Password: ");
        fflush(stdout);
        if (!fgets(in, sizeof(in), stdin)) break;
        
        size_t l = strlen(in);
        while (l > 0 && (in[l-1] == '\r' || in[l-1] == '\n')) in[--l] = 0;
        if (l == 0) continue;
        
        printf("[*] Contacting validation server at %s...\n", SERVER_HOST);
        int r = get_flag(in, f, sizeof(f));
        
        if (r == 1) {
            printf("\n[SUCCESS] Flag: %s\n\n", f);
            break;
        } else if (r == -1) {
            printf("\n[ERROR] Connection failed to validation node.\n");
            printf("        Do you think the verification server is localhost??\n\n");
            printf("        search for the Updated repo/;\n\n");
            printf("        May I forgot it private ?\n\n");
        } else if (r == -2) {
            printf("\n[DENIED] Password verification failed.\n\n");
        } else {
            printf("\n[ERROR] Unknown server error or misconfiguration.\n\n");
        }
    }
    
#ifdef _WIN32
    WSACleanup(); system("pause");
#endif
    return 0;
}
