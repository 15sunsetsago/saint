#include <asm-generic/socket.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>

#define SOCKET int
#define closesocket(s) close(s)

#define BUFFER_SIZE 1024 /* Pending Change */

const int server_port = 443;

static volatile bool server_running = true;

/**
    Mostly boilerplate
    -   Handle HTTP 301 Redirect (HTTP to HTTPS redirect)
    -   Multithread client handling
    -   Handle serving of main page
    -   Handle Routes
    -   Implement best practices from IBM Docs
    -   Create daemon for static site updating
        -   Update Makefile for options for compiling daemon or server
    -   Get certificate for aswium.com domain [X]
    -   Get a VPS and setup DNS in CloudFlare
*/

static SOCKET create_sock()
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
    addr.sin_port = htons(server_port);
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

    if (listen(s, 1) < 0)
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

int main()
{
    /* Initialization */
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    SOCKET server_sock = -1;
    SOCKET client_sock = -1;

    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);

    // char buffer[BUFFER_SIZE];
    // char *txbuf;

    char rxbuf[256];
    size_t rxcap = sizeof(rxbuf);

    int rxlen;

    ssl_ctx = create_context();
    configure_server_context(ssl_ctx);
    server_sock = create_sock();

    /* Main Server Loop */
    /* Multithread later so clients are handled concurrently */
    while(server_running)
    {
        client_sock = accept(server_sock, (struct sockaddr *)&addr, &addr_len);
        if (client_sock < 0 )
        {
            perror("Unable to Accept");
            exit(EXIT_FAILURE);
        }

        printf("Client TCP Connection Accepted\n");

        ssl = SSL_new(ssl_ctx);
        if (!SSL_set_fd(ssl, (int)client_sock))
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        
        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
            server_running = false;
        }
        else
        {
            printf("Client Connection Accepted\n\n");
        
            while (true) 
            {
                /* Get message from client; will fail if client closes connection */
                if ((rxlen = SSL_read(ssl, rxbuf, (int)rxcap)) <= 0) 
                {
                    if (rxlen == 0) 
                    {
                        printf("Client closed connection\n");
                    } 
                    else 
                    {
                        printf("SSL_read returned %d\n", rxlen);
                    }
                    ERR_print_errors_fp(stderr);
                    break;
                }

                /* Insure null terminated input */
                rxbuf[rxlen] = 0;
                /* Look for kill switch */
                if (strcmp(rxbuf, "kill\n") == 0) 
                {
                    /* Terminate...with extreme prejudice */
                    printf("Server received 'kill' command\n");
                    server_running = false;
                    break;
                }
                /* Show received message */
                printf("Received: %s", rxbuf);

                /* Form Hello World Text*/
                char test_buf[2048];
                int test_len;

                char *msg = "Hello, World!";

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

                /* Return Hello World */
                if (SSL_write(ssl, test_buf, test_len) <= 0) 
                {
                    ERR_print_errors_fp(stderr);
                }
            }
            if (server_running) 
            {
                /* Cleanup for next client */
                SSL_shutdown(ssl);
                SSL_free(ssl);
                closesocket(client_sock);
                /*
                 * Set client_skt to -1 to avoid double close when
                 * server_running become false before next accept
                 */
                client_sock = -1;
            }
        }
    }
    /* Cleanup (Upon finishing)*/
    if (ssl != NULL) 
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }   
    SSL_CTX_free(ssl_ctx);

    if (client_sock != -1)
        closesocket(client_sock);
    if (server_sock != -1)
        closesocket(server_sock);

    return EXIT_SUCCESS;
}