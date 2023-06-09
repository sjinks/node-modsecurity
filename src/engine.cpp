#include <memory>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rule_message.h>
#include "engine.h"

Napi::FunctionReference* ModSecurity::ctor = nullptr;

void ModSecurity::log_callback(void* data, const void* message)
{
    auto ref    = static_cast<Napi::ObjectReference*>(data);
    auto ms     = ref->Value();
    auto modsec = Napi::ObjectWrap<ModSecurity>::Unwrap(ms);

    if (!modsec->m_logger.IsEmpty()) {
        auto msg = static_cast<const char*>(message);
        auto env = ms.Env();
        modsec->m_logger.Call(ms, { Napi::String::New(env, msg) });
    }
}

Napi::Object ModSecurity::Init(Napi::Env env, Napi::Object exports)
{
    auto func = DefineClass(env, "ModSecurity", {
        InstanceMethod<&ModSecurity::setLogCallback>("setLogCallback", napi_default),
        InstanceMethod<&ModSecurity::whoAmI>("whoAmI", napi_default)
    });

    auto ref = std::make_unique<Napi::FunctionReference>();
    *ref     = Napi::Persistent(func);

    ModSecurity::ctor = ref.release();
    env.SetInstanceData<Napi::FunctionReference>(ModSecurity::ctor);

    exports.Set("ModSecurity", func);
    return exports;
}

void ModSecurity::Finalize(Napi::Env env)
{
    if (!this->m_logger.IsEmpty()) {
        this->m_logger.Unref();
    }
}

ModSecurity::ModSecurity(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<ModSecurity>(info)
{
    this->m_modsec.setConnectorInformation("ModSecurity/nodejs");
    this->m_modsec.setServerLogCb(&ModSecurity::log_callback, modsecurity::TextLogProperty);
}

Napi::Value ModSecurity::setLogCallback(const Napi::CallbackInfo& info)
{
    auto cb = info[0].As<Napi::Function>();
    if (!this->m_logger.IsEmpty()) {
        this->m_logger.Unref();
    }

    this->m_logger = Napi::Persistent(cb);
    return info.Env().Undefined();
}

Napi::Value ModSecurity::whoAmI(const Napi::CallbackInfo& info)
{
    return Napi::String::New(info.Env(), this->m_modsec.whoAmI());
}
