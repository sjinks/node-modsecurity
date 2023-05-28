#ifndef FC720BA6_AE93_4142_917C_3BC02BEFD1C7
#define FC720BA6_AE93_4142_917C_3BC02BEFD1C7

#include <napi.h>
#include <modsecurity/rules_set.h>

class Rules : public Napi::ObjectWrap<Rules> {
public:
    static Napi::FunctionReference* ctor;
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    explicit Rules(const Napi::CallbackInfo& info);

private:
    friend class Transaction;
    modsecurity::RulesSet m_rules;

    Napi::Value loadFromFile(const Napi::CallbackInfo& info);
    Napi::Value add(const Napi::CallbackInfo& info);
    Napi::Value dump(const Napi::CallbackInfo& info);
    Napi::Value merge(const Napi::CallbackInfo& info);
    Napi::Value length(const Napi::CallbackInfo& info);
};

#endif /* FC720BA6_AE93_4142_917C_3BC02BEFD1C7 */
