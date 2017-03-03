#include "Apns2Client.h"

#include <time.h>
#include <vector>


#define MAX_MSGSIZE (16 * 1024)
#define BLOCK_SECONDS (30)
#define INBUFF_SIZE (64 * 1024)
#define OUTBUFF_SIZE (64 * 1024)


#if _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

int PrivateKeyPassphraseCallback(char* pBuf, int size, int flag, void* userData)
{
	return Apns2Client::Instance()->OnPrivateKeyPassphraseCallback(pBuf, size, flag, userData);
}

#pragma  region Nghttp2 callbacks.
/*
* The implementation of nghttp2_send_callback type. Here we write
* |data| with size |length| to the network and return the number of
* bytes actually written. See the documentation of
* nghttp2_send_callback for the details.
*/
ssize_t Nghttp2SendCallback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
	Apns2Client* sender = (Apns2Client*)user_data;
	return sender->OnNghttp2SendCallback(session, data, length, flags, user_data);
}

/*
* The implementation of nghttp2_recv_callback type. Here we read data
* from the network and write them in |buf|. The capacity of |buf| is
* |length| bytes. Returns the number of bytes stored in |buf|. See
* the documentation of nghttp2_recv_callback for the details.
*/
ssize_t Nghttp2ReceiveCallback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data)
{
	Apns2Client* sender = (Apns2Client*)user_data;
	return sender->OnNghttp2ReceiveCallback(session, buf, length, flags, user_data);
}

static int Nghttp2OnFrameSendCallback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
	size_t i;
	switch (frame->hd.type) 
	{
	case NGHTTP2_HEADERS:
		if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) 
		{
			const nghttp2_nv *nva = frame->headers.nva;
			printf("[INFO] C ----------------------------> S (HEADERS)\n");
			for (i = 0; i < frame->headers.nvlen; ++i) 
			{
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

static int Nghttp2OnFrameReceiveCallback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
	switch (frame->hd.type) 
	{
	case NGHTTP2_HEADERS:
		if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) 
		{
			Apns2Client* sender = (Apns2Client*)user_data;//nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
			if (sender)
			{
				printf("[INFO] C <---------------------------- S (HEADERS end)\n");
			}
		}
		else 
		{
			printf("other header: %d", frame->headers.cat);
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

static int Nghttp2OnHeaderCallback(nghttp2_session *session, const nghttp2_frame *frame, 
	const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data) 
{
	if (frame->hd.type == NGHTTP2_HEADERS) 
	{
		fwrite(name, namelen, 1, stdout);
		printf(": ");
		fwrite(value, valuelen, 1, stdout);
		printf("\n");

	}
	return 0;
}

static int Nghttp2OnBeginHeadersCallback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
	printf("[INFO] C <---------------------------- S (HEADERS begin)\n");
	return 0;
}

/*
* The implementation of nghttp2_on_stream_close_callback type. We use
* this function to know the response is fully received. Since we just
* fetch 1 resource in this program, after reception of the response,
* we submit GOAWAY and close the session.
*/
static int Nghttp2OnStreamCloseCallback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) 
{
	Apns2Client* sender = (Apns2Client*)user_data;
	return sender->OnNghttp2StreamCloseCallback(session, stream_id, error_code, user_data);
}

/*
* The implementation of nghttp2_on_data_chunk_recv_callback type. We
* use this function to print the received response body.
*/
static int Nghttp2OnDataChunkRecvCallback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) 
{
	printf("%s\n", __FUNCTION__);
	char buf[1024] = { 0 };
	memcpy(buf, data, len);
	buf[len] = 0;
	printf("%s\n", buf);
	return 0;
}

ssize_t Nghttp2DataProviderReadCallback(nghttp2_session *session, int32_t stream_id,
	uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
	Apns2Client* sender = (Apns2Client*)user_data;
	return sender->OnNghttp2DataProviderReadcallback(session, stream_id, buf, length, data_flags, source, user_data);
}
#pragma endregion //Nghttp2 callbacks.

Apns2Client::Apns2Client()
{
	_socket = INVALID_SOCKET;

	_sslContext = 0;
	_ssl = 0;

	_nghttp2Session = 0;
	_isNghttp2StreamClosed = false;

	_privateKeyPath = GetApplicationPath() + "NotificationAppKey.pem";
	_certificatePath = GetApplicationPath() + "NotificationApp.pem";
	_password = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"; // TODO: Replace this with your password.
}

Apns2Client::~Apns2Client()
{
	Release();
}

Apns2Client* Apns2Client::Instance()
{
	static Apns2Client Apns2ClientInstance;
	return &Apns2ClientInstance;
}

bool Apns2Client::Init()
{
	bool result = false;
	do 
	{
		if (!InitSocket("api.development.push.apple.com", 443))
			break;

		if (!InitSSL())
			break;

		if (!InitNghttp2())
			break;
		result = true;
	} while (false);
	return result;
}

void Apns2Client::Release()
{
	ReleaseNghttp2();
	ReleaseSSL();
	ReleaseSocket();
}

bool Apns2Client::InitSocket(const char* host, int port, bool keepAlive /*= false*/)
{
	if (_socket != INVALID_SOCKET)
		return true;

	bool result = false;
	SOCKET socketResult = INVALID_SOCKET;
	do
	{
		struct hostent *remoteHost;
		struct in_addr remoteAddr;
		std::vector<std::string> remoteAddrs;
		if (!host)
		{
			break;
		}

		WSADATA wsaData;
		WORD version = MAKEWORD(2, 0);
		int ret = WSAStartup(version, &wsaData);
		if (ret)
		{
			break;
		}

		remoteHost = gethostbyname(host);
		if (remoteHost == nullptr)
		{
			int dwError = WSAGetLastError();
			if (dwError != 0)
			{
				if (dwError == WSAHOST_NOT_FOUND)
				{
					printf("Host not found\n");
					break;
				}
				else if (dwError == WSANO_DATA)
				{
					printf("No data record found\n");
					break;
				}
				else
				{
					printf("Function failed with error: %ld\n", dwError);
					break;
				}
			}
		}
		else
		{
			if (remoteHost->h_addrtype == AF_INET)
			{
				int i = 0;
				while (remoteHost->h_addr_list[i] != 0)
				{
					remoteAddr.s_addr = *(u_long *)remoteHost->h_addr_list[i++];
					remoteAddrs.push_back(inet_ntoa(remoteAddr));
					printf("\tIPv4 Address %d: %s\n", i, inet_ntoa(remoteAddr));
				}
			}
			else if (remoteHost->h_addrtype == AF_INET6)
			{
				printf("\tRemotehost is an IPv6 address\n");
				break;
			}
		}

		unsigned long addr = INADDR_NONE;
		for (auto& remoteAddr : remoteAddrs)
		{
			unsigned long remote = inet_addr(remoteAddr.c_str());
			if (remote != INADDR_NONE)
			{
				addr = remote;
				break;
			}
		}
		if (addr == INADDR_NONE)
		{
			break;
		}

		socketResult = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (socketResult == INVALID_SOCKET)
		{
			break;
		}

		if (keepAlive)
		{
			int optval = 1;
			if (setsockopt(socketResult, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(optval)))
			{
				break;
			}
		}

		sockaddr_in addr_in;
		memset((void*)&addr_in, 0, sizeof(addr_in));
		addr_in.sin_family = AF_INET;
		addr_in.sin_port = htons(port);
		addr_in.sin_addr.s_addr = addr;

		if (connect(socketResult, (sockaddr *)&addr_in, sizeof(addr_in)) == SOCKET_ERROR)
		{
			break;
		}

		/*timeval timeout;
		timeout.tv_sec = BLOCK_SECONDS;
		timeout.tv_usec = 0;
		fd_set writeset, exceptset;
		FD_ZERO(&writeset);
		FD_ZERO(&exceptset);
		FD_SET(socketResult, &writeset);
		FD_SET(socketResult, &exceptset);

		if (select(FD_SETSIZE, NULL, &writeset, &exceptset, &timeout) <= 0)
		{
			break;
		}
		else
		{
			if (FD_ISSET(socketResult, &exceptset))
			{
				break;
			}
		}

		struct linger ling;
		ling.l_onoff = 1;
		ling.l_linger = 500;
		setsockopt(socketResult, SOL_SOCKET, SO_LINGER, (const char*)&ling, sizeof(ling));*/

		// switch to async mode.
/*
#if _WIN32
		DWORD mode = 1;
		if (ioctlsocket(socketResult, FIONBIO, &mode) == SOCKET_ERROR)
		{
			break;
		}
#else
		fcntl(m_Socket, F_SETFL, O_NONBLOCK);
#endif*/

		result = true;
	} while (false);

	if (!result)
	{
		if (socketResult != INVALID_SOCKET)
		{
			closesocket(socketResult);
			WSACleanup();
			socketResult = INVALID_SOCKET;
		}
	}
	_socket = socketResult;

	return result;
}

void Apns2Client::ReleaseSocket()
{
	if (_socket == INVALID_SOCKET)
		return;

	closesocket(_socket);
	WSACleanup();
	_socket = INVALID_SOCKET;
}


bool Apns2Client::InitSSL()
{
	if (_ssl != nullptr)
		return true;

	if (!InitSSLContext(_privateKeyPath, _certificatePath))
		return false;
	
	if (!ConnectSSL())
		return false;

	return true;
}

int Apns2Client::OnPrivateKeyPassphraseCallback(char* pBuf, int size, int flag, void* userData)
{
	std::string pwd = _password;
	strncpy(pBuf, (char *)(pwd.c_str()), size);
	pBuf[size - 1] = '\0';
	if (size > pwd.length())
	{
		size = (int)pwd.length();
	}
	return size;
}

bool Apns2Client::InitSSLContext(const std::string& privateKeyPath, const std::string& certificatePath)
{
	if (_sslContext != nullptr)
		return true;

	static bool isSSLInitialized = false;
	if (!isSSLInitialized)
	{
		SSL_library_init();
		SSL_load_error_strings();
		isSSLInitialized = true;
	}

	int errorCode = 0;
	SSL_CTX* sslContext = 0;	
	do 
	{
		sslContext = SSL_CTX_new(SSLv23_client_method());
		SSL_CTX_set_options(sslContext, SSL_OP_ALL);
		SSL_CTX_set_mode(sslContext, SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_session_cache_mode(sslContext, SSL_SESS_CACHE_OFF);
		SSL_CTX_set_default_passwd_cb(sslContext, PrivateKeyPassphraseCallback);

		errorCode = SSL_CTX_use_PrivateKey_file(sslContext, privateKeyPath.c_str(), SSL_FILETYPE_PEM);
		if (errorCode != 1)
		{
			break;
		}

		errorCode = SSL_CTX_use_certificate_chain_file(sslContext, certificatePath.c_str());
		if (errorCode != 1)
		{
			break;
		}
		_sslContext = sslContext;
	} while (false);

	if (errorCode != 1 && sslContext != 0)
	{
		SSL_CTX_free(sslContext);
		sslContext = 0;
	}	
	return _sslContext != nullptr;
}

void Apns2Client::ReleaseSSLContext()
{
	if (_sslContext != nullptr)
	{
		SSL_CTX_free(_sslContext);
		_sslContext = nullptr;
	}
}

bool Apns2Client::ConnectSSL()
{
	if (_ssl != nullptr)
		return true;

	bool result = false;
	SSL* ssl = nullptr;
	BIO* bio = nullptr;
	do 
	{
		bio = BIO_new(BIO_s_socket());
		if (bio == nullptr)
		{
			printf("Cannot create SSL BIO object");
			break;
		}

		BIO_set_fd(bio, static_cast<int>(_socket), BIO_NOCLOSE);
		ssl = SSL_new(_sslContext);
		if (ssl == nullptr)
		{
			printf("Cannot create SSL object");
			break;
		}
		SSL_set_bio(ssl, bio, bio);

		int ret = SSL_connect(ssl);
		HandlerSSLError(ssl, ret);
		result = true;
		_ssl = ssl;
	} while (false);

	if (!result)
	{
		if (bio != nullptr)
			BIO_free(bio);

		if (ssl != nullptr)
			SSL_free(ssl);

		_ssl = nullptr;
	}
	return result;
}

int Apns2Client::HandlerSSLError(SSL* ssl, int rc)
{
	if (rc > 0) return rc;
		
	int sslError = SSL_get_error(ssl, rc);
	int error = WSAGetLastError();

	switch (sslError)
	{
	case SSL_ERROR_ZERO_RETURN:
		return 0;
	case SSL_ERROR_WANT_READ:
		return SSL_ERROR_WANT_READ; //SecureStreamSocket::ERR_SSL_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
		return SSL_ERROR_WANT_WRITE; //SecureStreamSocket::ERR_SSL_WANT_WRITE;
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_X509_LOOKUP:
		// these should not occur
#if _DEBUG
		throw;
#endif
		return rc;
	case SSL_ERROR_SYSCALL:
		// fallthrough
	default:
	{
		long lastError = ERR_get_error();
		if (lastError == 0)
		{			
		}
		else
		{
			char buffer[256];
			ERR_error_string_n(lastError, buffer, sizeof(buffer));
			std::string msg(buffer);
		}
	}
	break;
	}

	return rc;
}

void Apns2Client::ReleaseSSL()
{
	if (_ssl)
	{
		SSL_shutdown(_ssl);
		SSL_free(_ssl);
		_ssl = 0;
	}
	ReleaseSSLContext();
}

bool Apns2Client::InitNghttp2()
{
	if (_nghttp2Session != nullptr)
		return true;

	bool result = false;
	nghttp2_session_callbacks *callbacks = nullptr;	
	do 
	{
		int rv;
		nghttp2_session_callbacks *callbacks;
		rv = nghttp2_session_callbacks_new(&callbacks);
		if (rv != 0)
		{
			fprintf(stderr, "nghttp2_session_callbacks_new");
			break;
		}
		
		/*
		* Setup callback functions. nghttp2 API offers many callback
		* functions, but most of them are optional. The send_callback is
		* always required. Since we use nghttp2_session_recv(), the
		* recv_callback is also required.
		*/
		nghttp2_session_callbacks_set_send_callback(callbacks, Nghttp2SendCallback);
		nghttp2_session_callbacks_set_recv_callback(callbacks, Nghttp2ReceiveCallback);
		nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, Nghttp2OnFrameSendCallback);
		nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, Nghttp2OnFrameReceiveCallback);
		nghttp2_session_callbacks_set_on_header_callback(callbacks, Nghttp2OnHeaderCallback);
		nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, Nghttp2OnBeginHeadersCallback);
		nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, Nghttp2OnStreamCloseCallback);
		nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, Nghttp2OnDataChunkRecvCallback);

		rv = nghttp2_session_client_new(&_nghttp2Session, callbacks, this);
		if (rv != 0) 
		{
			fprintf(stderr, "nghttp2_session_client_new");
			break;
		}

		rv = nghttp2_submit_settings(_nghttp2Session, NGHTTP2_FLAG_NONE, NULL, 0);
		if (rv != 0) 
		{
			fprintf(stderr, "nghttp2_submit_settings %d", rv);
			break;
		}
		result = true;
	} while (false);

	if (!result)
	{
		if (callbacks != nullptr)
			nghttp2_session_callbacks_del(callbacks);

		if (_nghttp2Session != nullptr)
		{
			nghttp2_session_del(_nghttp2Session);
			_nghttp2Session = nullptr;
		}
	}
	return result;
}

void Apns2Client::ReleaseNghttp2()
{
	if (_nghttp2Session)
	{
		nghttp2_session_del(_nghttp2Session);
		_nghttp2Session = 0;
	}
}


ssize_t Apns2Client::OnNghttp2SendCallback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
	Apns2Client* sender = (Apns2Client*)user_data;
	ERR_clear_error();
	int rv = SSL_write(sender->_ssl, data, (int)length);
	if (rv <= 0)
	{
		int err = SSL_get_error(_ssl, rv);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
		{
			rv = NGHTTP2_ERR_WOULDBLOCK;
		}
		else
		{
			rv = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}
	return rv;
}

ssize_t Apns2Client::OnNghttp2ReceiveCallback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data)
{
	Apns2Client* sender = (Apns2Client*)user_data;
	ERR_clear_error();
	int rv = 0;
	if (!sender->_isNghttp2StreamClosed && sender->_nghttp2Session != nullptr)
	{
		rv = SSL_read(sender->_ssl, buf, length);
	}

	if (rv < 0)
	{
		int err = SSL_get_error(_ssl, rv);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
		{
			rv = NGHTTP2_ERR_WOULDBLOCK;
		}
		else
		{
			rv = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}
	else if (rv == 0)
	{
		rv = NGHTTP2_ERR_EOF;
	}
	return rv;
}

int Apns2Client::OnNghttp2StreamCloseCallback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{
	Apns2Client* apns2Client = (Apns2Client*)user_data;//nghttp2_session_get_stream_user_data(session, stream_id);
	if (apns2Client) 
	{
		/*int rv;
		rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

		if (rv != 0) 
		{
			diec("nghttp2_session_terminate_session", rv);
		}*/
		apns2Client->_isNghttp2StreamClosed = true;
	}
	return 0;
}

ssize_t Apns2Client::OnNghttp2DataProviderReadcallback(nghttp2_session *session, int32_t stream_id,
	uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
	int rv = 0;
	Apns2Client* apns2Client = (Apns2Client*)nghttp2_session_get_stream_user_data(session, stream_id);
	if (apns2Client)
	{
		memcpy(buf, apns2Client->_notificationMessage.c_str(), apns2Client->_notificationMessage.length());
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		rv = (int)apns2Client->_notificationMessage.length();

		printf("[INFO] C ----------------------------> S (DATA post body)\n");
		printf("%s\n", apns2Client->_notificationMessage.c_str());
	}
	return rv;
}

std::string Apns2Client::GetApplicationPath()
{
	static std::string applicationPath;
	if (applicationPath.empty())
	{
		char path[1024] = { 0 };
		GetModuleFileNameA(0, path, sizeof(path) / sizeof(char));
		applicationPath = path;
		applicationPath = applicationPath.substr(0, applicationPath.rfind('\\') + 1);
	}
	return applicationPath;
}

#include <Objbase.h>
std::string Apns2Client::CreateGUID()
{
	char chBuf[48] = { 0 };
	GUID guid;
	if (S_OK == CoCreateGuid(&guid))
	{
		sprintf(chBuf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", guid.Data1, guid.Data2, guid.Data3,
			guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	}
	return std::string(chBuf);
}

#define CharArrayToNV(name, value) \
{ \
	(uint8_t *) name, (uint8_t *)value, sizeof(name) - 1, sizeof(value) - 1, NGHTTP2_NV_FLAG_NONE \
}

#define StringToNV(name, value) \
{ \
	(uint8_t *)name, (uint8_t *)value, sizeof(name) - 1, strlen(value), NGHTTP2_NV_FLAG_NONE \
}

bool Apns2Client::PushNotification(const std::string& appBundleId, const std::string& deviceToken, const std::string& notificationMessage)
{
	if (appBundleId.empty() || deviceToken.empty() || notificationMessage.empty())
		return false;

	if (!Init())
		return false;

	_appBundleId = appBundleId;
	_deviceToken = deviceToken;

	// {\"aps\":{\"alert\":\"nghttp2 test.\",\"sound\":\"default\"}}
	_notificationMessage = notificationMessage;

	std::string guid = CreateGUID();
	std::string path = "/3/device/" + deviceToken;
	int32_t stream_id;
	nghttp2_nv nva[] =
	{
		CharArrayToNV(":method", "POST"),
		StringToNV(":path", path.c_str()),
		StringToNV("apns-topic", appBundleId.c_str()),
		StringToNV("apns-id", guid.c_str())
	};

	nghttp2_data_provider data_prd;
	data_prd.source.ptr = (void*)this;
	data_prd.read_callback = Nghttp2DataProviderReadCallback;

	_isNghttp2StreamClosed = false;
	stream_id = nghttp2_submit_request(_nghttp2Session, nullptr, nva, sizeof(nva) / sizeof(nva[0]), &data_prd, this);
	if (stream_id < 0)
		return false;

	int rv = 0;
	if (nghttp2_session_want_write(_nghttp2Session))
	{
		rv = nghttp2_session_send(_nghttp2Session);
	}
	if (nghttp2_session_want_read(_nghttp2Session))
	{
		rv = nghttp2_session_recv(_nghttp2Session);
	}
	return stream_id >= 0;
}

int main(int argc, const char *argv[])
{
	Apns2Client::Instance()->PushNotification("com.xxx.notificationapp", // TODO: Replace this with your app's bunld id.
		"72bf24178967ee4359bc7de2aeabXXXXX8d594f2b2459acc43a286e1db7e9XX", // TODO: Replace this with your user's device token.
		"{\"aps\":{\"alert\":\"nghttp2 test.\",\"sound\":\"default\"}}");


	Apns2Client::Instance()->PushNotification("com.xxx.notificationapp", // TODO: Replace this with your app's bunld id.
		"72bf24178967ee4359bc7de2aeabXXXXX8d594f2b2459acc43a286e1db7e9XX", // TODO: Replace this with your user's device token.
		"{ \"aps\" : { \"alert\" : \"Hi U\\r\\n This is your gift X!\", \"badge\" : 1, \"sound\" : \"blank.aiff\" } }");
	return 0;
}