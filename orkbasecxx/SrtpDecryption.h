
#ifndef __SRTP_DECRYPTION_H__
#define __SRTP_DECRYPTION_H__

#include "OrkBase.h"
#include <openssl/ssl.h>
#include <openssl/srtp.h>

class DLL_IMPORT_EXPORT_ORKBASE SrtpDecryption {
public:
    SrtpDecryption();
    ~SrtpDecryption();
    
    bool Initialize(unsigned char* key, size_t keyLen);
    bool DecryptRtpPacket(unsigned char* packet, size_t& len);
    
private:
    SRTP_CTX* m_ctx;
};

#endif
