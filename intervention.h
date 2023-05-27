#ifndef E7E1E782_CC78_499F_ACEB_A1D77CF5292C
#define E7E1E782_CC78_499F_ACEB_A1D77CF5292C

#include <napi.h>

class Intervention : public Napi::ObjectWrap<Intervention> {
public:
    static Napi::FunctionReference* ctor;
    static void Init(Napi::Env env);
    Intervention(const Napi::CallbackInfo& info);
};

#endif /* E7E1E782_CC78_499F_ACEB_A1D77CF5292C */
