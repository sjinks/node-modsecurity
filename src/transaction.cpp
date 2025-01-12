#include <cstddef>
#include <cstdlib>
#if __cplusplus >= 201703L
#   include <string_view>
#endif
#include <modsecurity/intervention.h>
#include <modsecurity/transaction.h>
#include "transaction.h"
#include "engine.h"
#include "rules.h"
#include "intervention.h"

#if __cplusplus >= 201703L
    using std::string_view;
#else
    using string_view = std::string;
#endif

Napi::Object Transaction::createIntervention(Napi::Env env, modsecurity::ModSecurityIntervention& it)
{
    auto result = Intervention::ctor->New({
        Napi::Number::New(env, it.status),
        it.url ? Napi::String::New(env, it.url) : env.Null(),
        it.log ? Napi::String::New(env, it.log) : env.Null(),
        Napi::Boolean::New(env, it.disruptive != 0)
    });

    modsecurity::intervention::free(&it);
    return result;
}

Napi::Object Transaction::Init(Napi::Env env, Napi::Object exports)
{
    Napi::Function func = DefineClass(env, "Transaction", {
        InstanceMethod<&Transaction::processConnection>("processConnection", napi_default),
        InstanceMethod<&Transaction::processURI>("processURI", napi_default),
        InstanceMethod<&Transaction::addRequestHeader>("addRequestHeader", napi_default),
        InstanceMethod<&Transaction::processRequestHeaders>("processRequestHeaders", napi_default),
        InstanceMethod<&Transaction::appendRequestBody>("appendRequestBody", napi_default),
        InstanceMethod<&Transaction::requestBodyFromFile>("requestBodyFromFile", napi_default),
        InstanceMethod<&Transaction::processRequestBody>("processRequestBody", napi_default),
        InstanceMethod<&Transaction::addResponseHeader>("addResponseHeader", napi_default),
        InstanceMethod<&Transaction::processResponseHeaders>("processResponseHeaders", napi_default),
        InstanceMethod<&Transaction::updateStatusCode>("updateStatusCode", napi_default),
        InstanceMethod<&Transaction::appendResponseBody>("appendResponseBody", napi_default),
        InstanceMethod<&Transaction::processResponseBody>("processResponseBody", napi_default),
        InstanceMethod<&Transaction::processLogging>("processLogging", napi_default),
    });

    exports.Set("Transaction", func);
    return exports;
}

void Transaction::Finalize(Napi::Env env)
{
    this->m_modsec.Unref();
    this->m_rules.Unref();
}

Transaction::Transaction(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Transaction>(info)
{
    auto env = info.Env();
    auto ms  = info[0].As<Napi::Object>();
    auto rs  = info[1].As<Napi::Object>();

    if (!ms.InstanceOf(ModSecurity::ctor->Value())) {
        throw Napi::TypeError::New(env, "Transaction::constructor() expects the first argument to be an instance of ModSecurity");
    }

    if (!rs.InstanceOf(Rules::ctor->Value())) {
        throw Napi::TypeError::New(env, "Transaction::constructor() expects the second argument to be an instance of Rules");
    }

    auto modsec = Napi::ObjectWrap<ModSecurity>::Unwrap(ms);
    auto rules  = Napi::ObjectWrap<Rules>::Unwrap(rs);

    this->m_modsec = Napi::Persistent(ms);
    this->m_rules  = Napi::Persistent(rs);

    this->m_transaction.reset(new modsecurity::Transaction(&modsec->m_modsec, &rules->m_rules, &this->m_modsec));
}

bool Transaction::hasIntervention(modsecurity::ModSecurityIntervention_t& it) const {
    modsecurity::intervention::clean(&it);
    return this->m_transaction->intervention(&it);
}

Napi::Value Transaction::processConnection(const Napi::CallbackInfo& info)
{
    auto env        = info.Env();
    auto clientIP   = info[0].ToString();
    auto clientPort = info[1].ToNumber();
    auto serverIP   = info[2].ToString();
    auto serverPort = info[3].ToNumber();

    if (true == this->m_transaction->processConnection(clientIP.Utf8Value().c_str(), clientPort.Int32Value(), serverIP.Utf8Value().c_str(), serverPort.Int32Value())) {
        modsecurity::ModSecurityIntervention it;
        if (this->hasIntervention(it)) {
            return Transaction::createIntervention(env, it);
        }

        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::processURI(const Napi::CallbackInfo& info)
{
    auto env      = info.Env();
    auto uri      = info[0].ToString();
    auto method   = info[1].ToString();
    auto protoVer = info[2].ToString();
    if (true == this->m_transaction->processURI(uri.Utf8Value().c_str(), method.Utf8Value().c_str(), protoVer.Utf8Value().c_str())) {
        modsecurity::ModSecurityIntervention it;
        if (this->hasIntervention(it)) {
            return Transaction::createIntervention(env, it);
        }

        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::addRequestHeader(const Napi::CallbackInfo& info)
{
    auto env = info.Env();

    if (info.Length() >= 2) {
        std::string n;
        std::string v;
        string_view name;
        string_view value;

        if (info[0].IsBuffer()) {
            auto buf = info[0].As<Napi::Buffer<char>>();
            name     = string_view(buf.Data(), buf.Length());
        } else {
            n    = info[0].ToString().Utf8Value();
            name = string_view(n);
        }

        if (info[1].IsBuffer()) {
            auto buf = info[1].As<Napi::Buffer<char>>();
            value    = string_view(buf.Data(), buf.Length());
        } else {
            v     = info[1].ToString().Utf8Value();
            value = string_view(v);
        }

        return Napi::Boolean::New(
            env,
            this->m_transaction->addRequestHeader(
                reinterpret_cast<const unsigned char*>(name.data()), name.size(),
                reinterpret_cast<const unsigned char*>(value.data()), value.size()
            )
        );
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::processRequestHeaders(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (true == this->m_transaction->processRequestHeaders()) {
        modsecurity::ModSecurityIntervention it;
        if (this->hasIntervention(it)) {
            return Transaction::createIntervention(env, it);
        }

        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::appendRequestBody(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() >= 1) {
        Napi::Value body = info[0];
        int res;
        if (body.IsBuffer()) {
            auto buf = body.As<Napi::Buffer<char>>();
            res      = this->m_transaction->appendRequestBody(reinterpret_cast<const unsigned char*>(buf.Data()), buf.Length());
        } else if (body.IsString()) {
            auto str = body.As<Napi::String>().Utf8Value();
            res      = this->m_transaction->appendRequestBody(reinterpret_cast<const unsigned char*>(str.c_str()), str.length());
        } else {
            throw Napi::TypeError::New(env, "Transaction::appendRequestBody() expects its argument to be a Buffer or String");
        }

        if (true == res) {
            modsecurity::ModSecurityIntervention it;
            if (this->hasIntervention(it)) {
                return Transaction::createIntervention(env, it);
            }

            return Napi::Boolean::New(env, true);
        }
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::requestBodyFromFile(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() >= 1) {
        Napi::String path = info[0].ToString();
        if (true == this->m_transaction->requestBodyFromFile(path.Utf8Value().c_str())) {
            modsecurity::ModSecurityIntervention it;
            if (this->hasIntervention(it)) {
                return Transaction::createIntervention(env, it);
            }

            return Napi::Boolean::New(env, true);
        }
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::processRequestBody(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (true == this->m_transaction->processRequestBody()) {
        modsecurity::ModSecurityIntervention it;
        if (this->hasIntervention(it)) {
            return Transaction::createIntervention(env, it);
        }

        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::addResponseHeader(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() >= 2) {
        std::string n;
        std::string v;
        string_view name;
        string_view value;

        if (info[0].IsBuffer()) {
            auto buf = info[0].As<Napi::Buffer<char>>();
            name     = string_view(buf.Data(), buf.Length());
        } else {
            n    = info[0].ToString().Utf8Value();
            name = string_view(n);
        }

        if (info[1].IsBuffer()) {
            auto buf = info[1].As<Napi::Buffer<char>>();
            value    = string_view(buf.Data(), buf.Length());
        } else {
            v     = info[1].ToString().Utf8Value();
            value = string_view(v);
        }

        return Napi::Boolean::New(
            env,
            this->m_transaction->addResponseHeader(
                reinterpret_cast<const unsigned char*>(name.data()), name.size(),
                reinterpret_cast<const unsigned char*>(value.data()), value.size()
            )
        );
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::processResponseHeaders(const Napi::CallbackInfo& info)
{
    auto env      = info.Env();
    auto code     = info[0].ToNumber();
    auto protoVer = info[1].ToString();

    if (true == this->m_transaction->processResponseHeaders(code.Int32Value(), protoVer.Utf8Value().c_str())) {
        modsecurity::ModSecurityIntervention it;
        if (this->hasIntervention(it)) {
            return Transaction::createIntervention(env, it);
        }

        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::updateStatusCode(const Napi::CallbackInfo& info)
{
    auto env  = info.Env();
    auto code = info[0].ToNumber();
    return Napi::Boolean::New(env, this->m_transaction->updateStatusCode(code.Int32Value()));
}

Napi::Value Transaction::appendResponseBody(const Napi::CallbackInfo& info)
{
    auto env  = info.Env();
    auto body = info[0];
    int res;
    if (body.IsBuffer()) {
        auto buf = body.As<Napi::Buffer<char>>();
        res      = this->m_transaction->appendResponseBody(reinterpret_cast<const unsigned char*>(buf.Data()), buf.Length());
    } else if (body.IsString()) {
        auto str = body.As<Napi::String>().Utf8Value();
        res      = this->m_transaction->appendResponseBody(reinterpret_cast<const unsigned char*>(str.c_str()), str.length());
    } else {
        throw Napi::TypeError::New(env, "Transaction::appendResponseBody() expects its argument to be a Buffer or String");
    }

    if (true == res) {
        modsecurity::ModSecurityIntervention it;
        if (this->hasIntervention(it)) {
            return Transaction::createIntervention(env, it);
        }

        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::processResponseBody(const Napi::CallbackInfo& info)
{
    auto env = info.Env();

    if (true == this->m_transaction->processResponseBody()) {
        modsecurity::ModSecurityIntervention it;
        if (this->hasIntervention(it)) {
            return Transaction::createIntervention(env, it);
        }

        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

Napi::Value Transaction::processLogging(const Napi::CallbackInfo& info)
{
    return Napi::Boolean::New(info.Env(), this->m_transaction->processLogging());
}
