#include "BLAKE3.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace hajimi::crypto {
namespace {
using CV = std::array<uint32_t,8>;
using Block = std::array<uint32_t,16>;
constexpr CV iv{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
constexpr uint32_t chunkStart=1, chunkEnd=2, parent=4, root=8,
                   keyedHash=16, deriveContext=32, deriveMaterial=64;
constexpr unsigned permutation[16]{2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};
uint32_t load(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24;
}
uint32_t rotr(uint32_t v, unsigned c) { return v>>c | v<<(32-c); }
void g(Block &s,unsigned a,unsigned b,unsigned c,unsigned d,uint32_t x,uint32_t y) {
    s[a]+=s[b]+x; s[d]=rotr(s[d]^s[a],16);
    s[c]+=s[d]; s[b]=rotr(s[b]^s[c],12);
    s[a]+=s[b]+y; s[d]=rotr(s[d]^s[a],8);
    s[c]+=s[d]; s[b]=rotr(s[b]^s[c],7);
}
void round(Block &s,const Block &m) {
    g(s,0,4,8,12,m[0],m[1]); g(s,1,5,9,13,m[2],m[3]);
    g(s,2,6,10,14,m[4],m[5]); g(s,3,7,11,15,m[6],m[7]);
    g(s,0,5,10,15,m[8],m[9]); g(s,1,6,11,12,m[10],m[11]);
    g(s,2,7,8,13,m[12],m[13]); g(s,3,4,9,14,m[14],m[15]);
}
Block compress(const CV &cv, Block block, uint64_t counter,uint32_t len,uint32_t flags) {
    Block state{cv[0],cv[1],cv[2],cv[3],cv[4],cv[5],cv[6],cv[7],
                iv[0],iv[1],iv[2],iv[3],uint32_t(counter),uint32_t(counter>>32),len,flags};
    for (unsigned r=0;r<7;++r) {
        round(state,block);
        if (r != 6) {
            Block permuted{};
            for (unsigned i=0;i<16;++i) permuted[i]=block[permutation[i]];
            block=permuted;
        }
    }
    for (unsigned i=0;i<8;++i) { state[i]^=state[i+8]; state[i+8]^=cv[i]; }
    return state;
}
struct Output {
    CV cv; Block block; uint64_t counter; uint32_t len, flags;
    CV chaining() const {
        Block result=compress(cv,block,counter,len,flags); CV out{};
        std::copy_n(result.begin(),8,out.begin()); return out;
    }
    Buffer bytes(size_t count) const {
        if (count > maximumQueuedBytes) throw std::runtime_error("BLAKE3 output exceeds safety limit");
        Buffer out; out.reserve(count);
        for (uint64_t index=0;out.size()<count;++index) {
            Block words=compress(cv,block,index,len,flags|root);
            for (uint32_t word:words) {
                for (unsigned i=0;i<4 && out.size()<count;++i) out.push_back(uint8_t(word>>(i*8)));
            }
        }
        return out;
    }
};
Output parentOutput(const CV &left,const CV &right,const CV &key,uint32_t flags) {
    Block block{}; std::copy(left.begin(),left.end(),block.begin());
    std::copy(right.begin(),right.end(),block.begin()+8);
    return {key,block,0,64,flags|parent};
}
struct Chunk {
    CV cv; uint64_t counter; uint32_t flags; unsigned len=0,blocks=0;
    std::array<uint8_t,64> buffer{};
    unsigned size() const { return 64*blocks+len; }
    uint32_t start() const { return blocks==0 ? chunkStart : 0; }
    Block words() const {
        Block result{};
        for (unsigned i=0;i<16;++i) result[i]=load(buffer.data()+i*4);
        return result;
    }
    void update(const uint8_t *data,size_t count) {
        while (count) {
            if (len==64) {
                Block result=compress(cv,words(),counter,64,flags|start());
                std::copy_n(result.begin(),8,cv.begin()); ++blocks; buffer.fill(0); len=0;
            }
            size_t take=std::min(size_t(64-len),count);
            std::copy_n(data,take,buffer.begin()+len); len+=unsigned(take); data+=take; count-=take;
        }
    }
    Output output() const { return {cv,words(),counter,len,flags|start()|chunkEnd}; }
};
Buffer hashMode(const CV &key,uint32_t flags,const Buffer &input,size_t count) {
    Chunk chunk{key,0,flags}; std::vector<CV> stack; stack.reserve(54);
    size_t remaining=input.size(), offset=0;
    while (remaining) {
        if (chunk.size()==1024) {
            CV value=chunk.output().chaining(); uint64_t total=chunk.counter+1, halves=total;
            while ((halves&1)==0) {
                value=parentOutput(stack.back(),value,key,flags).chaining(); stack.pop_back(); halves>>=1;
            }
            stack.push_back(value); chunk=Chunk{key,total,flags};
        }
        size_t take=std::min(size_t(1024-chunk.size()),remaining);
        chunk.update(input.data()+offset,take); remaining-=take; offset+=take;
    }
    Output output=chunk.output();
    for (auto it=stack.rbegin();it!=stack.rend();++it) output=parentOutput(*it,output.chaining(),key,flags);
    return output.bytes(count);
}
CV keyWords(const Buffer &key) {
    if (key.size()!=32) throw std::runtime_error("BLAKE3 keyed hash requires a 32-byte key");
    CV words{}; for (unsigned i=0;i<8;++i) words[i]=load(key.data()+i*4); return words;
}
}
Buffer blake3(const Buffer &input,size_t count) { return hashMode(iv,0,input,count); }
Buffer blake3Keyed(const Buffer &key,const Buffer &input,size_t count) {
    return hashMode(keyWords(key),keyedHash,input,count);
}
Buffer blake3DeriveKey(const std::string &context,const Buffer &material,size_t count) {
    Buffer bytes(context.begin(),context.end());
    Buffer contextKey=hashMode(iv,deriveContext,bytes,32);
    return hashMode(keyWords(contextKey),deriveMaterial,material,count);
}
} // namespace hajimi::crypto
