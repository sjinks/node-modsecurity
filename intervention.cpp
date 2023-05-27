#include <cstddef>
#include <cstdlib>
#include <modsecurity/intervention.h>
#include "intervention.h"

Napi::FunctionReference* Intervention::ctor = nullptr;

void Intervention::Init(Napi::Env env)
{
    auto func = DefineClass(env, "Intervention", {});

    Intervention::ctor = new Napi::FunctionReference();
    *Intervention::ctor = Napi::Persistent(func);
    env.SetInstanceData<Napi::FunctionReference>(Intervention::ctor);
}

Intervention::Intervention(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Intervention>(info)
{
    Napi::Object self = info.This().As<Napi::Object>();
    self.DefineProperties({
        Napi::PropertyDescriptor::Value("status", info[0], napi_enumerable),
        Napi::PropertyDescriptor::Value("url", info[1], napi_enumerable),
        Napi::PropertyDescriptor::Value("log", info[2], napi_enumerable),
        Napi::PropertyDescriptor::Value("disruptive", info[3], napi_enumerable)
    });
}
