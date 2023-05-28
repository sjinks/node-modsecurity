#ifndef C5AADECE_76C1_4942_AADD_19237F6A9784
#define C5AADECE_76C1_4942_AADD_19237F6A9784

#include <napi.h>
#include <modsecurity/modsecurity.h>

class ModSecurity : public Napi::ObjectWrap<ModSecurity> {
public:
    static Napi::FunctionReference* ctor;
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    explicit ModSecurity(const Napi::CallbackInfo& info);

    void Finalize(Napi::Env env) override;

private:
    friend class Transaction;

    modsecurity::ModSecurity m_modsec;
    Napi::FunctionReference m_logger;

    Napi::Value setLogCallback(const Napi::CallbackInfo& info);
    Napi::Value whoAmI(const Napi::CallbackInfo& info);

    static void log_callback(void* data, const void* message);
};

#endif /* C5AADECE_76C1_4942_AADD_19237F6A9784 */
