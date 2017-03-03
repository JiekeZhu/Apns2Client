#pragma once

#include <winsock2.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <nghttp2/nghttp2.h>

#include <string>

class Apns2Client
{
private:
	Apns2Client();
	~Apns2Client();
public:
	static Apns2Client* Instance();

public:
	bool Init();
	void Release();
	
	bool PushNotification(const std::string& appBundleId, const std::string& deviceToken, const std::string& notificationMessage);

public:
	std::string GetApplicationPath();
	std::string CreateGUID();
public:
	int OnPrivateKeyPassphraseCallback(char* pBuf, int size, int flag, void* userData);
	/*
	* The implementation of nghttp2_send_callback type. Here we write
	* |data| with size |length| to the network and return the number of
	* bytes actually written. See the documentation of
	* nghttp2_send_callback for the details.
	*/
	ssize_t OnNghttp2SendCallback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data);

	/*
	* The implementation of nghttp2_recv_callback type. Here we read data
	* from the network and write them in |buf|. The capacity of |buf| is
	* |length| bytes. Returns the number of bytes stored in |buf|. See
	* the documentation of nghttp2_recv_callback for the details.
	*/
	ssize_t OnNghttp2ReceiveCallback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data);
	
	/*
	* The implementation of nghttp2_on_stream_close_callback type. We use
	* this function to know the response is fully received. Since we just
	* fetch 1 resource in this program, after reception of the response,
	* we submit GOAWAY and close the session.
	*/
	int OnNghttp2StreamCloseCallback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data);

	/**
	* The callback function to read a chunk of data from the |source|.
	*/
	ssize_t OnNghttp2DataProviderReadcallback(nghttp2_session *session, int32_t stream_id,
		uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data);
private:
	bool InitSocket(const char* host, int port, bool keepAlive = false);
	void ReleaseSocket();

	bool InitSSLContext(const std::string& privateKeyPath, const std::string& certificatePath);
	void ReleaseSSLContext();

	bool InitSSL();
	bool ConnectSSL();
	void ReleaseSSL();
	int HandlerSSLError(SSL* ssl, int rc);

	bool InitNghttp2();
	void ReleaseNghttp2();

private:
	SOCKET _socket;
	SSL_CTX* _sslContext;
	SSL* _ssl;

	nghttp2_session *_nghttp2Session;
	bool _isNghttp2StreamClosed;

	std::string _privateKeyPath;
	std::string _certificatePath;
	std::string _password;

	std::string _appBundleId;
	std::string _deviceToken;
	std::string _notificationMessage;
};

