#include <napi.h>

#include "engine.h"
#include "rules.h"
#include "transaction.h"
#include "intervention.h"

static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    ModSecurity::Init(env, exports);
    Rules::Init(env, exports);
    Transaction::Init(env, exports);
    Intervention::Init(env);
    return exports;
}

NODE_API_MODULE(modsecurity, Init);
