#include <nan.h>
#include <iostream>
#include <stdint.h>
#include <sstream>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
    #include "neoscrypt.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "s3.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "x14.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "dcrypt.h"
    #include "jh.h"
    #include "x5.h"
    #include "c11.h"
}

#include "boolberry.h"
#include "nrghash.h"
#include "block.h"

namespace Buffer = node::Buffer;
using namespace v8;


NAN_METHOD(quark) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(x11) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}


NAN_METHOD(nrghash) {
    using namespace energi;
    
    Nan::HandleScope scope;

    if (info.Length() < 9) {
        return Nan::ThrowError("You must provide ten arguments");
    }

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if (!Buffer::HasInstance(target)) {
        return Nan::ThrowError("Argument should be a buffer object.");
    }
    BlockHeader header;
    header.nVersion = Nan::To<int32_t>(info[1]).FromJust();
    header.hashPrevBlock.SetHex(*Nan::Utf8String(Nan::To<String>(info[2]).ToLocalChecked()));
    header.hashMerkleRoot.SetHex(*Nan::Utf8String(Nan::To<String>(info[3]).ToLocalChecked()));
    header.nTime = Nan::To<uint32_t>(info[4]).FromJust();
    header.nBits = Nan::To<uint32_t>(info[5]).FromJust();
    header.nHeight = Nan::To<uint32_t>(info[6]).FromJust();
    header.hashMix.SetHex(*Nan::Utf8String(Nan::To<String>(info[7]).ToLocalChecked()));
    header.nNonce = strtoull(
        *Nan::Utf8String(Nan::To<String>(info[8]).ToLocalChecked()), nullptr, 16);

    CBlockHeaderTruncatedLE truncatedBlockHeader(header);
    n_nrghash::h256_t headerHash(&truncatedBlockHeader, sizeof(truncatedBlockHeader));
    n_nrghash::result_t ret = n_nrghash::light::hash(n_nrghash::cache_t(header.nHeight), headerHash, header.nNonce);
    
    auto res = uint256(ret.value);

    info.GetReturnValue().Set(Nan::CopyBuffer(
        (char*)res.begin(), res.size()).ToLocalChecked());
}

NAN_METHOD(blockhash) {
    using namespace energi;
    
    Nan::HandleScope scope;

    if (info.Length() < 9) {
        return Nan::ThrowError("You must provide ten arguments");
    }

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    
    if (!Buffer::HasInstance(target)) {
        return Nan::ThrowError("Argument should be a buffer object.");
    }
    BlockHeader header;
    header.nVersion = Nan::To<int32_t>(info[1]).FromJust();
    header.hashPrevBlock.SetHex(*Nan::Utf8String(Nan::To<String>(info[2]).ToLocalChecked()));
    header.hashMerkleRoot.SetHex(*Nan::Utf8String(Nan::To<String>(info[3]).ToLocalChecked()));
    header.nTime = Nan::To<uint32_t>(info[4]).FromJust();
    header.nBits = Nan::To<uint32_t>(info[5]).FromJust();
    header.nHeight = Nan::To<uint32_t>(info[6]).FromJust();
    header.hashMix.SetHex(*Nan::Utf8String(Nan::To<String>(info[7]).ToLocalChecked()));
    header.nNonce = strtoull(
        *Nan::Utf8String(Nan::To<String>(info[8]).ToLocalChecked()), nullptr, 16);

    CBlockHeaderFullLE fullBlockHeader(header);
    n_nrghash::h256_t blockHash(&fullBlockHeader, sizeof(fullBlockHeader));
    uint256  res = uint256(blockHash);

    info.GetReturnValue().Set(Nan::CopyBuffer(
        (char*)res.begin(), res.size()).ToLocalChecked());
}

NAN_METHOD(x5) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(scrypt) {
   Nan::HandleScope scope;

   if (info.Length() < 3)
       return Nan::ThrowError("You must provide buffer to hash, N value, and R value");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       return Nan::ThrowError("Argument should be a buffer object.");

   unsigned int nValue = Nan::To<int>(info[1]).FromJust();
   unsigned int rValue = Nan::To<int>(info[2]).FromJust();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(neoscrypt_hash) {
    Nan::HandleScope scope;

    if (info.Length() < 2)
        return Nan::ThrowError("You must provide two arguments.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    neoscrypt(input, output, 0);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}


NAN_METHOD(scryptn) {
   Nan::HandleScope scope;

   if (info.Length() < 2)
       return Nan::ThrowError("You must provide buffer to hash and N factor.");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       return Nan::ThrowError("Argument should be a buffer object.");

   unsigned int nFactor = Nan::To<int>(info[1]).FromJust();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now

   info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(scryptjane) {
    Nan::HandleScope scope;

    if (info.Length() < 5)
        return Nan::ThrowError("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("First should be a buffer object.");

    int timestamp = Nan::To<int>(info[1]).FromJust();
    int nChainStartTime = Nan::To<int>(info[2]).FromJust();
    int nMin = Nan::To<int>(info[3]).FromJust();
    int nMax = Nan::To<int>(info[4]).FromJust();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(yescrypt) {
   Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       return Nan::ThrowError("Argument should be a buffer object.");

   char * input = Buffer::Data(target);
   char output[32];

   yescrypt_hash(input, output);

   info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(keccak) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}


NAN_METHOD(bcrypt) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    bcrypt_hash(input, output);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(skein) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    skein_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}


NAN_METHOD(groestl) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}


NAN_METHOD(groestlmyriad) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}


NAN_METHOD(blake) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(dcrypt) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    dcrypt_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(fugue) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}


NAN_METHOD(qubit) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(s3) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    s3_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(hefty1) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}


NAN_METHOD(shavite3) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(cryptonight) {
    Nan::HandleScope scope;

    bool fast = false;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    if (info.Length() >= 2) {
        if(!info[1]->IsBoolean())
            return Nan::ThrowError("Argument 2 should be a boolean");
        fast = Nan::To<bool>(info[1]).FromJust();
    }

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(x13) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(x14) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x14_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(boolberry) {
    Nan::HandleScope scope;

    if (info.Length() < 2)
        return Nan::ThrowError("You must provide two arguments.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    Local<Object> target_spad = Nan::To<Object>(info[1]).ToLocalChecked();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        return Nan::ThrowError("Argument 2 should be a buffer object.");

    if(info.Length() >= 3) {
        if(info[2]->IsUint32()) {
            height = Nan::To<uint32_t>(info[2]).FromJust();
        } else {
            return Nan::ThrowError("Argument 3 should be an unsigned integer.");
        }
    }

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(nist5) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(sha1) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(x15) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(fresh) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(jh) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    jh_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_METHOD(c11) {
    Nan::HandleScope scope;

    if (info.Length() < 1)
        return Nan::ThrowError("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return Nan::ThrowError("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    c11_hash(input, output);

    info.GetReturnValue().Set(Nan::CopyBuffer(output, sizeof(output)).ToLocalChecked());
}

NAN_MODULE_INIT(init) {
    using v8::FunctionTemplate;

    Nan::Set(target, Nan::New("quark").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(quark)).ToLocalChecked());
    Nan::Set(target, Nan::New("x11").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(x11)).ToLocalChecked());
    Nan::Set(target, Nan::New("scrypt").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(scrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("scryptn").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(scryptn)).ToLocalChecked());
    Nan::Set(target, Nan::New("scryptjane").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(scryptjane)).ToLocalChecked());
    Nan::Set(target, Nan::New("yescrypt").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(yescrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("keccak").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(keccak)).ToLocalChecked());
    Nan::Set(target, Nan::New("bcrypt").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(bcrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("skein").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(skein)).ToLocalChecked());
    Nan::Set(target, Nan::New("groestl").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(groestl)).ToLocalChecked());
    Nan::Set(target, Nan::New("groestlmyriad").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(groestlmyriad)).ToLocalChecked());
    Nan::Set(target, Nan::New("blake").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(blake)).ToLocalChecked());
    Nan::Set(target, Nan::New("fugue").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(fugue)).ToLocalChecked());
    Nan::Set(target, Nan::New("qubit").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(qubit)).ToLocalChecked());
    Nan::Set(target, Nan::New("hefty1").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(hefty1)).ToLocalChecked());
    Nan::Set(target, Nan::New("shavite3").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(shavite3)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("x13").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(x13)).ToLocalChecked());
    Nan::Set(target, Nan::New("x14").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(x14)).ToLocalChecked());
    Nan::Set(target, Nan::New("boolberry").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(boolberry)).ToLocalChecked());
    Nan::Set(target, Nan::New("nist5").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(nist5)).ToLocalChecked());
    Nan::Set(target, Nan::New("sha1").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(sha1)).ToLocalChecked());
    Nan::Set(target, Nan::New("x15").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(x15)).ToLocalChecked());
    Nan::Set(target, Nan::New("fresh").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(fresh)).ToLocalChecked());
    Nan::Set(target, Nan::New("s3").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(s3)).ToLocalChecked());
    Nan::Set(target, Nan::New("neoscrypt").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(neoscrypt_hash)).ToLocalChecked());
    Nan::Set(target, Nan::New("dcrypt").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(dcrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("jh").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(jh)).ToLocalChecked());
    Nan::Set(target, Nan::New("c11").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(c11)).ToLocalChecked());
    Nan::Set(target, Nan::New("nrghash").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(nrghash)).ToLocalChecked());
    Nan::Set(target, Nan::New("blockhash").ToLocalChecked(),
        Nan::GetFunction(Nan::New<FunctionTemplate>(blockhash)).ToLocalChecked());
}

NODE_MODULE(multihashing, init)
