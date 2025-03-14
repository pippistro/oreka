
#ifndef __DTLS_HANDLING_H__
#define __DTLS_HANDLING_H__

#include "OrkBase.h"
#include <openssl/ssl.h>
#include <openssl/srtp.h>

class DLL_IMPORT_EXPORT_ORKBASE DtlsContext {
public:
    DtlsContext();
    ~DtlsContext();
    
    bool ExtractSrtpKeys(SSL* ssl, unsigned char* clientKey, unsigned char* serverKey);
    bool IsDtls12Handshake(const unsigned char* buffer, size_t length);
    SSL_CTX* GetContext() { return m_ctx; }
    
private:
    static const int SRTP_MASTER_KEY_LEN = 30;
    SSL_CTX* m_ctx;
};

#endif
