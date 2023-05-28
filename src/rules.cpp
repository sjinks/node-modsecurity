#include <memory>
#include <modsecurity/rules_set.h>
#include "rules.h"

Napi::FunctionReference* Rules::ctor = nullptr;

Napi::Object Rules::Init(Napi::Env env, Napi::Object exports)
{
    Napi::Function func = DefineClass(env, "Rules", {
        InstanceMethod<&Rules::loadFromFile>("loadFromFile", napi_default),
        InstanceMethod<&Rules::add>("add", napi_default),
        InstanceMethod<&Rules::dump>("dump", napi_default),
        InstanceMethod<&Rules::merge>("merge", napi_default),
        InstanceAccessor<&Rules::length>("length", napi_default)
    });

    auto ref = std::make_unique<Napi::FunctionReference>();
    *ref     = Napi::Persistent(func);

    Rules::ctor = ref.release();
    env.SetInstanceData<Napi::FunctionReference>(Rules::ctor);

    exports.Set("Rules", func);
    return exports;
}

Rules::Rules(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Rules>(info)
{
}

Napi::Value Rules::loadFromFile(const Napi::CallbackInfo& info)
{
    auto env  = info.Env();
    auto path = info[0].ToString();
    int res = this->m_rules.loadFromUri(path.Utf8Value().c_str());
    if (res < 0) {
        auto err = this->m_rules.getParserError();
        throw Napi::Error::New(env, err);
    }

    return Napi::Boolean::New(env, true);
}

Napi::Value Rules::add(const Napi::CallbackInfo& info)
{
    auto env   = info.Env();
    auto rules = info[0].ToString();
    int res = this->m_rules.load(rules.Utf8Value().c_str());
    if (res < 0) {
        auto err = this->m_rules.getParserError();
        throw Napi::Error::New(env, err);
    }

    return Napi::Boolean::New(env, true);
}

Napi::Value Rules::dump(const Napi::CallbackInfo& info)
{
    this->m_rules.dump();
    return info.Env().Undefined();
}

Napi::Value Rules::merge(const Napi::CallbackInfo& info)
{
    auto env = info.Env();
    auto obj = info[0].As<Napi::Object>();
    if (obj.InstanceOf(Rules::ctor->Value())) {
        auto others = Napi::ObjectWrap<Rules>::Unwrap(obj);
        int res = this->m_rules.merge(&others->m_rules);
        if (res < 0) {
            auto err = this->m_rules.getParserError();
            throw Napi::Error::New(env, err);
        }

        return Napi::Boolean::New(env, true);
    }

    throw Napi::TypeError::New(env, "Rules::merge() expects the first argument must be an instance of Rules");
}

Napi::Value Rules::length(const Napi::CallbackInfo& info)
{
    auto phases = this->m_rules.m_rulesSetPhases;
    std::size_t result = 0;
    for (auto i = 0; i < modsecurity::Phases::NUMBER_OF_PHASES; ++i) {
        result += phases[i]->m_rules.size();
    }

    return Napi::Number::New(info.Env(), static_cast<double>(result));
}
