
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
    
    // Quick pre-check for efficiency
    if (buffer[0] != 22) return false; // Not a handshake
    
    // Use OpenSSL BIO to properly identify DTLS messages
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        LOG4CXX_ERROR(s_dtlsLog, "Failed to create BIO for DTLS detection");
        return false;
    }
    
    BIO_write(bio, buffer, length);
    SSL* ssl = SSL_new(m_ctx);
    if (!ssl) {
        LOG4CXX_ERROR(s_dtlsLog, "Failed to create SSL for DTLS detection");
        BIO_free(bio);
        return false;
    }
    
    SSL_set_bio(ssl, bio, bio);
    SSL_set_accept_state(ssl);
    
    // Peek at the data to see if it's a DTLS handshake
    int ret = SSL_peek(ssl, buffer, 1);
    int err = SSL_get_error(ssl, ret);
    bool isDtls = (err == SSL_ERROR_WANT_READ); // This indicates it's a DTLS handshake
    
    if (isDtls) {
        LOG4CXX_DEBUG(s_dtlsLog, "DTLS handshake detected");
    }
    
    SSL_free(ssl); // This also frees the BIO
    return isDtls;
}
