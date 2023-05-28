#ifndef AFE1A35A_A06D_4DEC_9F1A_C1A0EEF92CC9
#define AFE1A35A_A06D_4DEC_9F1A_C1A0EEF92CC9

#include <memory>
#include <napi.h>

namespace modsecurity {
    class Transaction;
    struct ModSecurityIntervention_t;
}

class Transaction : public Napi::ObjectWrap<Transaction> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    explicit Transaction(const Napi::CallbackInfo& info);

    void Finalize(Napi::Env env) override;

private:
    std::unique_ptr<modsecurity::Transaction> m_transaction;
    Napi::ObjectReference m_modsec;
    Napi::ObjectReference m_rules;

    Napi::Value processConnection(const Napi::CallbackInfo& info);
    Napi::Value processURI(const Napi::CallbackInfo& info);
    Napi::Value addRequestHeader(const Napi::CallbackInfo& info);
    Napi::Value processRequestHeaders(const Napi::CallbackInfo& info);
    Napi::Value appendRequestBody(const Napi::CallbackInfo& info);
    Napi::Value requestBodyFromFile(const Napi::CallbackInfo& info);
    Napi::Value processRequestBody(const Napi::CallbackInfo& info);
    Napi::Value addResponseHeader(const Napi::CallbackInfo& info);
    Napi::Value processResponseHeaders(const Napi::CallbackInfo& info);
    Napi::Value updateStatusCode(const Napi::CallbackInfo& info);
    Napi::Value appendResponseBody(const Napi::CallbackInfo& info);
    Napi::Value processResponseBody(const Napi::CallbackInfo& info);
    Napi::Value processLogging(const Napi::CallbackInfo& info);

    bool hasIntervention(modsecurity::ModSecurityIntervention_t& it) const;
    static Napi::Object createIntervention(Napi::Env env, modsecurity::ModSecurityIntervention_t& it);
};

#endif /* AFE1A35A_A06D_4DEC_9F1A_C1A0EEF92CC9 */
