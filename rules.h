#ifndef FC720BA6_AE93_4142_917C_3BC02BEFD1C7
#define FC720BA6_AE93_4142_917C_3BC02BEFD1C7

#include <memory>
#include <napi.h>

namespace modsecurity {
    class RulesSet;
}

class Rules : public Napi::ObjectWrap<Rules> {
public:
    static Napi::FunctionReference* ctor;
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    Rules(const Napi::CallbackInfo& info);

    operator modsecurity::RulesSet*() const;
private:
    std::unique_ptr<modsecurity::RulesSet> m_rules;

    Napi::Value loadFromFile(const Napi::CallbackInfo& info);
    Napi::Value add(const Napi::CallbackInfo& info);
    Napi::Value dump(const Napi::CallbackInfo& info);
    Napi::Value merge(const Napi::CallbackInfo& info);
    Napi::Value length(const Napi::CallbackInfo& info);
};

#endif /* FC720BA6_AE93_4142_917C_3BC02BEFD1C7 */
