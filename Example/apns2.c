#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <windows.h>



#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <nghttp2/nghttp2.h>


enum {
    IO_NONE,
    WANT_READ,
    WANT_WRITE
};

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,   \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_CS(NAME, VALUE)                                                \
  {                                                                            \
    (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),       \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

struct connection_t {
    int fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    nghttp2_session *session;
    int want_io;
};

struct uri_t 
{
    const char *url;
    const char *prefix;
    const char *token;
    uint16_t port;
    const char *cert;
    char *path;
};

struct request_t {
    struct uri_t uri;
    uint8_t *data;
    size_t data_len;
};

struct loop_t {
    int epfd;
};

static void
die(const char *msg)
{
    fprintf(stderr, "FATAL: %s\n", msg);
    exit(EXIT_FAILURE);
}

static void
diec(const char *msg,int i)
{
    fprintf(stderr, "FATAL: %s %d\n", msg,i);
    exit(EXIT_FAILURE);
}

static bool
file_exsit(const char *f)
{
    return 0 == access(f, 0) ? true : (printf("file not exsit:%s\n",f),false);
}

static bool
option_is_test(int argc, const char *arg1)
{
    if (argc == 2 && 0 == strcmp(arg1, "test")) {
        return true;
    } else {
        return false;
    }
}

static bool
option_is_regular(int argc, const char *token, const char *cert, const char *msg)
{
    if (argc == 4 && file_exsit(cert) && (msg!=NULL)) {
        return true;
    } else {
        return false;
    }
}

struct uri_t
make_uri(const char *url, uint16_t port, const char *prefix, const char *token ,const char *cert)
{
    struct uri_t uri;
    uri.url = url;
    uri.port = port;
    uri.prefix = prefix;
    uri.token = token;
    uri.cert = cert;

    uri.path = malloc(strlen(prefix)+strlen(token)+1);
    memset(uri.path,0,strlen(prefix)+strlen(token)+1);
    strcat(uri.path,prefix);
    strcat(uri.path,token);
    return uri;
}

static void
init_global_library()
{
    SSL_library_init();
    SSL_load_error_strings();
}

static int
connect_to_url(const char *url, uint16_t port)
{
    int sockfd;
    int rv;
    struct addrinfo hints, *res, *ressave;
    char port_str[6];

    bzero(&hints, sizeof(struct addrinfo));
    bzero(port_str, sizeof(port_str));
    snprintf(port_str, 6, "%d", port);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    printf("ns looking up ...\n");
    rv = getaddrinfo(url, port_str, &hints, &res);
    if (rv != 0) {
        freeaddrinfo(res);
        return -1;
    }

    ressave = res;
    do {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if(sockfd < 0) {
            continue;
        }
        struct in_addr a = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
        const char *p = inet_ntoa(a);
        printf("connecting to : %s\n",p);
        while ((rv = connect(sockfd, res->ai_addr, res->ai_addrlen)) == -1 &&
                errno == EINTR)
            ;
        if (0 == rv) {
            freeaddrinfo(ressave);
            return sockfd;
        } else {
            close(sockfd);
        }
    } while ((res = res->ai_next) != NULL);

    freeaddrinfo(ressave);
    return -1; 
}

static bool
socket_connect(const struct uri_t *uri, struct connection_t *conn)
{
    int fd;
    fd = connect_to_url(uri->url,uri->port);
    if (fd > 0) {
        conn->fd = fd;
        printf("socket connect ok: fd=%d, host: %s:%d\n", conn->fd, uri->url, uri->port);
        return true;
    }
    die("socket connect fail.");
    return false;
}

static X509*
read_x509_certificate(const char* path)
{
    BIO  *bio = NULL;
    X509 *x509 = NULL;
    if (NULL == (bio = BIO_new_file(path, "r"))) {
        return NULL;
    }
    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return x509;
}

/*
 * Callback function for TLS NPN. Since this program only supports
 * HTTP/2 protocol, if server does not offer HTTP/2 the nghttp2
 * library supports, we terminate program.
 */
static int
select_next_proto_cb(SSL *ssl, unsigned char **out,
                     unsigned char *outlen, const unsigned char *in,
                     unsigned int inlen, void *arg)
{
    int rv;
  /* nghttp2_select_next_protocol() selects HTTP/2 protocol the
     nghttp2 library supports. */
    rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
    if (rv <= 0) {
        die("Server did not advertise HTTP/2 protocol");
    }
    return SSL_TLSEXT_ERR_OK;
}

static void
init_ssl_ctx(SSL_CTX *ssl_ctx)
{
  /* Disable SSLv2 and enable all workarounds for buggy servers */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  /* Set NPN callback */
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
}

static bool
ssl_allocate(struct connection_t *conn, const char *cert)
{
    int rv;
    X509 *x509 = NULL;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    if (NULL == (x509 = read_x509_certificate(cert))) {
        return false;
    }

    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL) {
        X509_free(x509);
    }
    init_ssl_ctx(ssl_ctx);
    
    rv = SSL_CTX_use_certificate(ssl_ctx, x509);
    X509_free(x509);
    if (rv != 1) {
        SSL_CTX_free(ssl_ctx);
        return false;
    }

    rv = SSL_CTX_use_PrivateKey_file(ssl_ctx, cert, SSL_FILETYPE_PEM);
    if (rv != 1) {
        SSL_CTX_free(ssl_ctx);
        return false;
    }  

    rv = SSL_CTX_check_private_key(ssl_ctx);
    if (rv != 1) {
        SSL_CTX_free(ssl_ctx);
        return false;
    }  

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ssl_ctx);
        return false;
    }    
    
    conn->ssl_ctx = ssl_ctx;
    conn->ssl = ssl;
    return true;
}

static bool
ssl_handshake(SSL *ssl, int fd)
{
    int rv;
    if (SSL_set_fd(ssl, fd) == 0) {
        return false;
    }
    ERR_clear_error();
    //rv = SSL_connect(ssl);
    SSL_set_connect_state(ssl);
    rv = SSL_do_handshake(ssl);

    if(rv==1) {
            printf("Connected with encryption: %s\n", SSL_get_cipher(ssl));
    }
    if (rv <= 0) {
	printf("rv = %d\n",rv);
	unsigned long ssl_err = SSL_get_error(ssl,rv);
	int geterror = ERR_peek_error();
	int reason = ERR_GET_REASON(geterror);
	printf("rv %d, ssl_error %lu, get_err %d, reason %d \n",rv, ssl_err, geterror ,reason);
	printf("errmsg: %s\n", ERR_error_string(ERR_get_error(), NULL));
	        printf("errmsg msg: %s\n", ERR_reason_error_string(ERR_peek_error()));
	        printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
	    switch(reason)
	    {
	        case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED: /*,define in <openssl/ssl.h> "sslv3 alert certificate expired"},*/
	          reason = X509_V_ERR_CERT_HAS_EXPIRED;
	            printf("1\n");
	            break;
	        case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED: /*,"sslv3 alert certificate revoked"},*/
	          reason = X509_V_ERR_CERT_REVOKED;
	            printf("1\n");

	            break;
	    }

        fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        return false;
    }
    return true;
}

static bool
ssl_connect(const struct uri_t *uri, struct connection_t *conn)
{
    if (ssl_allocate(conn,uri->cert)) {
        fprintf(stdout, "ssl allocation ok\n");
    } else {
        fprintf(stderr, "ssl allocation error\n");
        return false;
    }

    fprintf(stderr, "ssl handshaking ...\n");
    if (ssl_handshake(conn->ssl, conn->fd)) {
        fprintf(stderr, "ssl handshake ok\n");
    } else {
        fprintf(stderr, "ssl handshake error\n");
        return false;
    }
    
    return true;
}

// callback impelement
#define _U_
/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *session _U_, const uint8_t *data,
                             size_t length, int flags _U_, void *user_data) {

  int rv;
  struct connection_t *conn = user_data;
  conn->want_io = IO_NONE;
  ERR_clear_error();
  rv = SSL_write(conn->ssl, data, (int)length);
  if (rv <= 0) {
    int err = SSL_get_error(conn->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      conn->want_io =
          (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return rv;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
static ssize_t recv_callback(nghttp2_session *session _U_, uint8_t *buf,
                             size_t length, int flags _U_, void *user_data) {

  struct connection_t *conn;
  int rv;
  conn = (struct connection_t *)user_data;
  conn->want_io = IO_NONE;
  ERR_clear_error();
  rv = SSL_read(conn->ssl, buf, (int)length);
  if (rv < 0) {
    int err = SSL_get_error(conn->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      conn->want_io =
          (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else if (rv == 0) {
    rv = NGHTTP2_ERR_EOF;
  }
  return rv;
}

static int on_frame_send_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data _U_) {
  size_t i;
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
      const nghttp2_nv *nva = frame->headers.nva;
      printf("[INFO] C ----------------------------> S (HEADERS)\n");
      for (i = 0; i < frame->headers.nvlen; ++i) {
        fwrite(nva[i].name, nva[i].namelen, 1, stdout);
        printf(": ");
        fwrite(nva[i].value, nva[i].valuelen, 1, stdout);
        printf("\n");
      }
    }
    break;
  case NGHTTP2_RST_STREAM:
    printf("[INFO] C ----------------------------> S (RST_STREAM)\n");
    break;
  case NGHTTP2_GOAWAY:
    printf("[INFO] C ----------------------------> S (GOAWAY)\n");
    break;
  }
  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data _U_) {
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      struct connection_t *conn = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      if (conn) {
        printf("[INFO] C <---------------------------- S (HEADERS end)\n");
      }
    } else {
	printf("other header: %d",frame->headers.cat);
    }
    break;
  case NGHTTP2_RST_STREAM:
    printf("[INFO] C <---------------------------- S (RST_STREAM)\n");
    break;
  case NGHTTP2_GOAWAY:
    printf("[INFO] C <---------------------------- S (GOAWAY)\n");
    break;
  }
  return 0;
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags, void *user_data) {

  if (frame->hd.type == NGHTTP2_HEADERS) {
        fwrite(name, namelen, 1, stdout);
        printf(": ");
        fwrite(value, valuelen, 1, stdout);
        printf("\n");

  }
  return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                                 const nghttp2_frame *frame,
                                                 void *user_data) {
  printf("[INFO] C <---------------------------- S (HEADERS begin)\n");
  return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code _U_,
                                    void *user_data _U_) {
  struct connection_t *conn = nghttp2_session_get_stream_user_data(session, stream_id);
  if (conn) {
    int rv;
    rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

    if (rv != 0) {
      diec("nghttp2_session_terminate_session", rv);
    }
  }
  return 0;
}

/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags _U_, int32_t stream_id,
                                       const uint8_t *data, size_t len,
                                       void *user_data _U_) {
  printf("%s\n",__FUNCTION__);
  char buf[1024] = {0};
  memcpy(buf,data,len);
  buf[len]=0;
  printf("%s\n",buf);
  return 0;
}

/*
 * Setup callback functions. nghttp2 API offers many callback
 * functions, but most of them are optional. The send_callback is
 * always required. Since we use nghttp2_session_recv(), the
 * recv_callback is also required.
 */
static void
setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{
  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
  nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks,on_header_callback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);

}

static bool
set_nghttp2_session_info(struct connection_t *conn)
{
    int rv;
    nghttp2_session_callbacks *callbacks;

    rv = nghttp2_session_callbacks_new(&callbacks);
    if (rv != 0) {
        fprintf(stderr, "nghttp2_session_callbacks_new");
    }
    setup_nghttp2_callbacks(callbacks);
    rv = nghttp2_session_client_new(&conn->session, callbacks, conn);
    if (rv != 0) {
        fprintf(stderr, "nghttp2_session_client_new");
    }
    nghttp2_session_callbacks_del(callbacks);

    rv = nghttp2_submit_settings(conn->session, NGHTTP2_FLAG_NONE, NULL, 0);
    if (rv != 0) {
	fprintf(stderr, "nghttp2_submit_settings %d",rv);
    }
    return true;
}

static struct request_t
make_request(struct uri_t uri, const char *msg)
{
    struct request_t req;
    req.uri = uri;
    req.data_len = strlen(msg);
    req.data = malloc(req.data_len);
    memcpy(req.data, msg, req.data_len);
    return req;
}

static int
set_nonblocking(int fd)
{
    int flags, rv;
    while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
        ;
    if (flags == -1) {
        return -1;
    }
    while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
        ;
    if (rv == -1) {
        return -1;
    }
    return 0;
}

static int
set_tcp_nodelay(int fd)
{
    int val = 1;
    if(-1 == setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val))) {
        return -1;
    }
    return 0;
}

ssize_t data_prd_read_callback(
    nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
    uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
  struct request_t *req = source->ptr;
  memcpy(buf,req->data,req->data_len);
  *data_flags |= NGHTTP2_DATA_FLAG_EOF;

  printf("[INFO] C ----------------------------> S (DATA post body)\n");
  char payload[1024];
  memcpy(payload,req->data,req->data_len);
  payload[req->data_len]=0;
  printf("%s\n",payload);
  return req->data_len;
}

static int32_t
submit_request(struct connection_t *conn, const struct request_t* req)
{
    int32_t stream_id;
    const nghttp2_nv nva[] = {
	      MAKE_NV(":method", "POST"),
	      MAKE_NV_CS(":path", req->uri.path),
	      MAKE_NV("apns-topic", "jpush.wangwei.test"),
	      MAKE_NV("apns-id", "e77a3d12-bc9f-f410-a127-43f212597a9c")
    };

    nghttp2_data_provider data_prd;
    data_prd.source.ptr = (void*)req;
    data_prd.read_callback = data_prd_read_callback;

    stream_id = nghttp2_submit_request(conn->session, NULL, nva,
                                       sizeof(nva) / sizeof(nva[0]), &data_prd, conn);
    return stream_id;
}


static void
event_loop(struct loop_t *loop, struct connection_t *conn)
{
  /*struct epoll_event ev,events[20];
  int epfd = loop->epfd;

  ev.data.fd = conn->fd;
  ev.events=EPOLLIN|EPOLLOUT;
  epoll_ctl(epfd,EPOLL_CTL_ADD,conn->fd,&ev);
  while (nghttp2_session_want_read(conn->session) ||
         nghttp2_session_want_write(conn->session)) {
	int nfds=epoll_wait(epfd,events,20,-1);
	int i;
	for(i=0;i<nfds;++i) {
	    int rv;
	    if(events[i].events & EPOLLIN) {
		  rv = nghttp2_session_recv(conn->session);
		  if (rv != 0) {
		    diec("nghttp2_session_recv", rv);
		  }
		  ev.data.fd=events[i].data.fd;
		  ev.events = EPOLLOUT;
		  epoll_ctl(epfd,EPOLL_CTL_MOD,events[i].data.fd,&ev);

	    } else if(events[i].events & EPOLLOUT) {
		  rv = nghttp2_session_send(conn->session);
		  if (rv != 0) {
		    diec("nghttp2_session_send", rv);
		  }
		  ev.data.fd=events[i].data.fd;
		  ev.events = EPOLLIN;
		  epoll_ctl(epfd,EPOLL_CTL_MOD,events[i].data.fd,&ev);
	    } else {
		if ((events[i].events & EPOLLHUP) || (events[i].events & EPOLLERR)) {
		    epoll_ctl(epfd,EPOLL_CTL_DEL,events[i].data.fd,NULL);
		} else {
		    printf("%s\n","epoll other");
		}
	    }
	}
  }*/
}

static bool
blocking_post(struct loop_t *loop, struct connection_t *conn, const struct request_t *req)
{
    set_nonblocking(conn->fd);
    set_tcp_nodelay(conn->fd);

    int32_t stream_id;
    stream_id = submit_request(conn, req);
    if (stream_id < 0) {
	printf("stream id error: %d\n",stream_id);
	return false;
    }

    printf("[INFO] Stream ID = %d\n", stream_id);

    loop->epfd = epoll_create1(0);

    if (loop->epfd < 0) {
	printf("epoll_create fail : %d\n", loop->epfd);
	return false;
    }

    /* maybe running in a thread */
    event_loop(loop,conn);

    close(loop->epfd);
    loop->epfd = -1;
    printf("over.\n");
    return true;
}

static void
connection_cleanup(struct connection_t *conn)
{
  if (conn->session &&
      conn->ssl &&
      conn->ssl_ctx) {
    nghttp2_session_del(conn->session);
    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
    SSL_CTX_free(conn->ssl_ctx);
    shutdown(conn->fd, SHUT_WR);
    close(conn->fd); 
  }
}

void
usage()
{
    printf("usage: apns2demo token cert message \n");
}

static void test();

int
main(int argc, const char *argv[])
{
#ifdef _WIN32
	{
		WORD wVersionRequested;
		WSADATA wsaData;
		int err;

		wVersionRequested = MAKEWORD(2, 2);

		err = WSAStartup(wVersionRequested, &wsaData);
		if (err != 0) 
		{
			printf("WSAStartup failed with error: %d\n", err);
			return 0;
		}
	}
#endif

    struct connection_t conn;
    struct uri_t uri;
    struct loop_t loop;
    const char *msg;

    if (argc == 1) {
        /* default: my test device info */
        uri = make_uri("api.push.apple.com", 2197, "/3/device/",
		       "73f98e1833fa744403fb4447e0f3a054d43f433b80e48c5bcaa62b501fd0f956",

		       "1fa5281c6c1d4cf5bb0bbbe0_dis_certkey.pem"); // cacert + privkey

        msg="{\"aps\":{\"alert\":\"nghttp2 test.\",\"sound\":\"default\"}}";
    } else if (option_is_test(argc,argv[1])) {
        test();
        exit(0);
    } else if (option_is_regular(argc, argv[1], argv[2], argv[3])) {
        /* production */
        uri = make_uri("api.push.apple.com", 2197, "/3/device/", argv[1], argv[2]);
        msg = argv[3];
    } else {
        usage();
        exit(0);
    }


    printf("nghttp2 version: %s\n", NGHTTP2_VERSION);
    printf("tls/ssl version: %s\n", SSL_TXT_TLSV1_2);

    init_global_library();
    
    socket_connect(&uri, &conn);
    if(!ssl_connect(&uri, &conn))
      die("ssl connect fail.");
    set_nghttp2_session_info(&conn);

    struct request_t req = make_request(uri,msg);
    blocking_post(&loop, &conn, &req);

    connection_cleanup(&conn);

#ifdef _WIN32
	WSACleanup();
#endif

    return 0;
}

static void
test()
{
  // bad path

  // invalid token

  // feedback

  //

}
