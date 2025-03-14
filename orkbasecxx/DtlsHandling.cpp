
#include "DtlsHandling.h"
#include "LogManager.h"

static LoggerPtr s_dtlsLog = Logger::getLogger("dtls");

DtlsContext::DtlsContext() {
    SSL_library_init();
    m_ctx = SSL_CTX_new(DTLS_method());
    if (m_ctx) {
        SSL_CTX_set_srtp_profiles(m_ctx, "SRTP_AES128_CM_SHA1_80");
    }
}

DtlsContext::~DtlsContext() {
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
    }
}

bool DtlsContext::ExtractSrtpKeys(SSL* ssl, unsigned char* clientKey, unsigned char* serverKey) {
    unsigned char material[SRTP_MASTER_KEY_LEN * 2];
    if (SSL_export_keying_material(ssl, material, sizeof(material), "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0) != 1) {
        LOG4CXX_ERROR(s_dtlsLog, "Failed to extract SRTP keying material");
        return false;
    }
    
    memcpy(clientKey, material, SRTP_MASTER_KEY_LEN);
    memcpy(serverKey, material + SRTP_MASTER_KEY_LEN, SRTP_MASTER_KEY_LEN);
    return true;
}

bool DtlsContext::IsDtls12Handshake(const unsigned char* buffer, size_t length) {
    if (length < 13) return false;
    
    // DTLS 1.2 handshake detection
    return (buffer[0] == 22 && // Handshake type
            buffer[1] == 254 && // DTLS 1.0
            buffer[2] == 255 && // Version
            buffer[13] == 1);   // Client Hello
}
