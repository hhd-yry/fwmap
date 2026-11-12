/* 动态验证执行链路的「合成靶子」——不是固件，是用来证明 dyn 的判断是真的。
 *
 * 行为刻意模仿固件里的一个脆弱 handler：
 *   POST /goform/formTest   body: X=<任意长度>
 *   → strcpy 进 64 字节的栈缓冲区
 *
 * 小于 64 字节不崩；超过就盖掉返回地址，进程被信号/保护打死。
 * 这样 crash / no-crash 两种状态都能用真实进程复现。
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>

static void handle(const char *body)
{
    char sbuf[64];
    /* 故意脆弱：就是固件里最常见的那一行 */
    strcpy(sbuf, body);
    printf("handled %d bytes\n", (int)strlen(sbuf));
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 8080;
    WSADATA wsa;
    SOCKET s, c;
    struct sockaddr_in addr;
    char buf[65536];
    int n;
    char *body;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    s = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((u_short)port);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        printf("bind failed on %d\n", port);
        return 2;
    }
    listen(s, 1);
    printf("listening %d\n", port);
    fflush(stdout);

    c = accept(s, NULL, NULL);
    n = recv(c, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return 3;
    buf[n] = 0;
    body = strstr(buf, "\r\n\r\n");
    body = body ? body + 4 : buf;
    if (strncmp(body, "X=", 2) == 0) body += 2;

    send(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", 38, 0);
    closesocket(c);
    closesocket(s);

    handle(body);
    return 0;
}
