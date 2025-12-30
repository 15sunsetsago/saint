#include <asm-generic/socket.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/epoll.h> 

#define SOCKET int
#define closesocket(s) close(s)

#define BUFFER_SIZE 1024 /* Pending Change */
#define MAX_EVENTS  10   /* Note: SOMAXCONN is 4096 */

const int server_port = 443;

static volatile bool server_running = true;

/**
    -   Handle HTTP 301 Redirect (HTTP to HTTPS redirect)
        -   Listen on two ports (80 and 443) for HTTP and HTTPS (Two Sockets)
            -   Requests made through port 80 are automatically redirected to Port 443 via HTTP 301 or 308
        -   use poll() or epoll() to listen for activity on both sockets
    -   Multithread client handling
        -   Threadpool
        -   Task Queue
    -   Handle serving of main page
    -   Handle Routes
    -   Implement best practices from IBM Docs
    -   Create daemon for static site updating
        -   Update Makefile for options for compiling daemon or server
    -   Get certificate for aswium.com domain [X]
    -   Get a VPS and setup DNS in CloudFlare
*/

static SOCKET create_sock(int port)
{
    SOCKET s;
    int optval = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);

    if(s < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    int t = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void*)&optval, sizeof(optval));
    if (t < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    // Increase queue size for socket from 1 to OS Max
    if (listen(s, SOMAXCONN) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr); 
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static void configure_server_context(SSL_CTX *ctx)
{
    /* Migrate from using self-signed certs to official CA */
    if (SSL_CTX_use_certificate_chain_file(ctx, "/etc/letsencrypt/live/aswium.com/fullchain.pem") <= 0)
    { 
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/letsencrypt/live/aswium.com/privkey.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

/**
    -   Crucial note is that there is no two-way connection, we simply read a GET request, respond appropriately, then kill the connection
*/

int main()
{
    /**
        Initialization
    */
    /* HTTP Initialization */
    SOCKET http_server_sock = create_sock(80);
    SOCKET http_client_sock = -1;
    struct sockaddr_in http_addr;
    unsigned int http_addr_len = sizeof(http_addr);


    /* HTTPS Initialization */
    SOCKET https_server_sock = create_sock(443);
    SOCKET https_client_sock = -1;
    struct sockaddr_in https_addr;    // addr for HTTPS connections
    unsigned int https_addr_len = sizeof(https_addr);   

    /* SSL Initialization */
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    ssl_ctx = create_context();
    configure_server_context(ssl_ctx);

    /* Vars for holding client message (Could make it port specific) */
    char client_msg_buf[4096];
    size_t client_msg_cap = sizeof(client_msg_buf);
    int client_msg_len;

    /**
        EPOLL SETUP
    */
    struct epoll_event ev, events[MAX_EVENTS];
    int epollfd, num_ready_fd;

    epollfd = epoll_create1(0);
    if (epollfd == -1)
    {
        perror("Failed to create epoll");
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLIN; // trigger event is when there is data to read
    ev.data.fd = http_server_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, http_server_sock, &ev) == -1)
    {
        perror("Failed to add http server socket to epoll_event");
        exit(EXIT_FAILURE);
    }

    ev.data.fd = https_server_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, https_server_sock, &ev) == -1)
    {
        perror("Failed to add https server socket to epoll event");
        exit(EXIT_FAILURE);
    }

    /* Main Server Loop */
    while(1)
    {
        num_ready_fd = epoll_wait(epollfd, events, MAX_EVENTS, -1); // Indefinitely wait for event
        if (num_ready_fd == -1)
        {
            perror("epoll_wait() initialization failed");
            exit(EXIT_FAILURE);
        }

        /* Reaching here means an event has occurred */
        /**
            -   Essentially, we keep populating the epoll event queue until there are no more new events or we have reached the maximum amount of events
            -   The events are handled after population
            -   We are using edge triggered so we must read everything in the buffer before the event is destroyed 
            -   Reminder: Write code to completely flush buffers after request is handled (Proper cleanup)
                -   Could just create instances at a lower scope instead
        */
        for (int n = 0; n < num_ready_fd; ++n)
        {
            SOCKET active_sock = events[n].data.fd;

            /* Accept HTTP request */
            if (active_sock == http_server_sock)
            {
                http_client_sock = accept(http_server_sock, (struct sockaddr *)&http_addr, &http_addr_len);
                if (http_client_sock < 0)
                {
                    perror("Unable to accept http request");
                    exit(EXIT_FAILURE);
                }
                printf("New connection via HTTP\n");

                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = http_client_sock;
                epoll_ctl(epollfd, EPOLL_CTL_ADD, http_client_sock, &ev);
            }

            /* Accept HTTPS request*/
            else if (active_sock == https_server_sock)
            {
                https_client_sock = accept(https_server_sock, (struct sockaddr *) &https_addr, &https_addr_len);
                if (https_client_sock < 0)
                {
                    perror("Unable to accept https request");
                    exit(EXIT_FAILURE);
                }
                printf("New connection via HTTPS\n");

                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = https_client_sock;
                epoll_ctl(epollfd, EPOLL_CTL_ADD, https_client_sock, &ev);
            }

            /* Handle the requests*/
            else
            {
                if (active_sock == http_client_sock)
                {
                    char buf[2048] = {0};
                    int msg_len = recv(http_client_sock, buf, 2048, 0);
                    if (msg_len > 0)
                    {
                        char *msg = "Hello, Port 80 Connection!";
                        char test_buf[2048];
                        int test_len;

                        test_len = snprintf(test_buf, sizeof(test_buf),
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: %d\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                            "%s",
                            (int) strlen(msg),
                            msg
                        );
                        send(http_client_sock, test_buf, test_len, 0);
                    }

                    /* Cleanup for next client */
                    closesocket(http_client_sock);
                    /*
                    * Set client_skt to -1 to avoid double close when
                    * server_running become false before next accept
                    */
                    http_client_sock = -1;
                }

                else if (active_sock == https_client_sock)
                {
                    ssl = SSL_new(ssl_ctx);

                    if(!SSL_set_fd(ssl, (int)https_client_sock))
                    {
                        ERR_print_errors_fp(stderr);
                        exit(EXIT_FAILURE);
                    }

                    if (SSL_accept(ssl) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        break;
                    }
                    while(1)
                    {
                        client_msg_len = SSL_read(ssl, client_msg_buf, (int) client_msg_cap);
                        if (client_msg_len > 0)
                        {
                            printf("Recieved: %s\n", client_msg_buf);
                            char *msg = "Hello, World!";
                            char test_buf[2048];
                            int test_len;

                            test_len = snprintf(test_buf, sizeof(test_buf),
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: %d\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "%s",
                                (int) strlen(msg),
                                msg
                            );
                            if (SSL_write(ssl, test_buf, test_len) <= 0) ERR_print_errors_fp(stderr);
                        }
                        else if (client_msg_len <= 0)
                        {
                            if (client_msg_len == 0) printf("Client closed connection\n");
                            else printf("SSL_read returned %d\n", client_msg_len);
                            ERR_print_errors_fp(stderr);
                            break;
                        }
                        else 
                        {
                            printf("SSL_read returned %d\n", client_msg_len);
                            ERR_print_errors_fp(stderr);
                            break;
                        }
                    }

                    /* Cleanup for next client */
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    closesocket(https_client_sock);
                    /*
                    * Set client_skt to -1 to avoid double close when
                    * server_running become false before next accept
                    */
                    https_client_sock = -1;
                }

            }
        }
    }

    /**
        Cleanup
    */
    if (ssl != NULL)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (https_client_sock != -1) closesocket(https_client_sock);
    if (https_server_sock != -1) closesocket(https_server_sock);

    if (http_client_sock != -1) closesocket(http_client_sock);
    if (http_server_sock != -1) closesocket(http_server_sock);

    return EXIT_SUCCESS;
}