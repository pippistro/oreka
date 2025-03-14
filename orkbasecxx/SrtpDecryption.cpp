
#include "SrtpDecryption.h"
#include "LogManager.h"

static LoggerPtr s_srtpLog = Logger::getLogger("srtp");

SrtpDecryption::SrtpDecryption() : m_ctx(NULL) {
}

SrtpDecryption::~SrtpDecryption() {
    if(m_ctx) {
        srtp_dealloc(m_ctx);
    }
}

bool SrtpDecryption::Initialize(unsigned char* key, size_t keyLen) {
    srtp_policy_t policy;
    memset(&policy, 0, sizeof(policy));
    
    crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
    crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
    
    policy.ssrc.type = ssrc_any_inbound;
    policy.key = key;
    policy.window_size = 128;
    policy.allow_repeat_tx = 0;
    
    if(srtp_create(&m_ctx, &policy) != err_status_ok) {
        LOG4CXX_ERROR(s_srtpLog, "Failed to create SRTP context");
        return false;
    }
    return true;
}

bool SrtpDecryption::DecryptRtpPacket(unsigned char* packet, size_t& len) {
    if(!m_ctx) return false;
    
    err_status_t status = srtp_unprotect(m_ctx, packet, (int*)&len);
    if(status != err_status_ok) {
        LOG4CXX_ERROR(s_srtpLog, "Failed to decrypt SRTP packet");
        return false;
    }
    return true;
}
