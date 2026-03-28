#include "Controller.h"

void Controller::generateContext(bool serialize)
{
    CCParams<CryptoContextCKKSRNS> params;

    params.SetBatchSize(slotNum);
    params.SetRingDim(1 << 16);//默认用16位环维度
    params.SetNumLargeDigits(3);
    params.SetSecurityLevel(HEStd_128_classic);//128安全级别
    params.SetSecretKeyDist(SPARSE_TERNARY);//稀疏三元矩阵

    level_budget= {4,4};//重新设立限制等级

    params.SetScalingTechnique(FLEXIBLEAUTO);
    params.SetFirstModSize(52);
    params.SetScalingModSize(47);

    uint32_t approxBootstrapDepth = 4 + 4;//近似自举深度由ctsLevels和stcLevels决定
    uint32_t level4Use = 10;//卷积和批量归一化需要额外的3层

    circuitDepth=level4Use+FHECKKSRNS::GetBootstrapDepth(approxBootstrapDepth, level_budget, SPARSE_TERNARY);
    //初始层级和重线性化层级无法被用于计算

    params.SetMultiplicativeDepth(circuitDepth);

    this->context=GenCryptoContext(params);

    context->Enable(PKE);
    context->Enable(KEYSWITCH);//密钥切换，用于在不同层级之间切换密钥

    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    context->Enable(FHE);

    keyPair=context->KeyGen();

    context->EvalMultKeyGen(keyPair.secretKey);//生成评估乘法密钥

    if(!serialize){ return;}

    ofstream multKey("../"+controllerFolder+"/multKey.txt",ios::out|ios::binary);
    if(multKey.is_open()){
        if(!context->SerializeEvalMultKey(multKey,SerType::BINARY)){
            exit(1);
        }
        multKey.close();
    }else{exit(1);}

    if(!Serial::SerializeToFile("../"+controllerFolder+"/context.txt",context,SerType::BINARY)){
        exit(1);
    }

    if(!Serial::SerializeToFile("../" + controllerFolder + "/public-key.txt", keyPair.publicKey, SerType::BINARY)){
        exit(1);
    }

    if(!Serial::SerializeToFile("../" + controllerFolder + "/secret-key.txt", keyPair.secretKey, SerType::BINARY)){
        exit(1);
    }
}

void Controller::generateContext(int logRing,int logScale,int logPrimes,int digitsHks,int ctsLevels,int stcLevels,int reluDeg,bool serialize=false)
{
    CCParams<CryptoContextCKKSRNS> params;

    params.SetBatchSize(1<<14);
    params.SetRingDim(1 << logRing);
    params.SetScalingModSize(1<<logScale);
    params.SetNumLargeDigits(digitsHks);
    params.SetSecurityLevel(HEStd_128_classic);//128安全级别
    params.SetSecretKeyDist(SPARSE_TERNARY);//稀疏三元矩阵生成私钥多项式

    level_budget= vector<uint32_t>();//重新设立限制等级

    level_budget.push_back(ctsLevels);
    level_budget.push_back(stcLevels);

    params.SetScalingModSize(logPrimes);
    params.SetScalingTechnique(FLEXIBLEAUTO);
    params.SetFirstModSize(logScale);

    uint32_t approxBootstrapDepth = 4 + 4;//近似自举深度由ctsLevels和stcLevels决定
    uint32_t level4Use = relu_depth[reluDeg]+3;//卷积和批量归一化需要额外的3层

    write_to_file("../" + controllerFolder + "/relu_degree.txt", to_string(reluDeg));
    write_to_file("../" + controllerFolder + "/level_budget.txt", to_string(level_budget[0]) + "," + to_string(level_budget[1]));

    circuitDepth=level4Use+FHECKKSRNS::GetBootstrapDepth(approxBootstrapDepth, level_budget, SPARSE_TERNARY);
    //初始层级和重线性化层级无法被用于计算

    params.SetMultiplicativeDepth(circuitDepth);

    this->context=GenCryptoContext(params);

    context->Enable(PKE);
    context->Enable(KEYSWITCH);//密钥切换，用于在不同层级之间切换密钥

    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    context->Enable(FHE);

    keyPair=context->KeyGen();

    context->EvalMultKeyGen(keyPair.secretKey);//生成评估乘法密钥

    if(!serialize){ return;}

    ofstream multKey("../"+controllerFolder+"/multKey.txt",ios::out|ios::binary);
    if(multKey.is_open()){
        if(!context->SerializeEvalMultKey(multKey,SerType::BINARY)){
            exit(1);
        }
        multKey.close();
    }else{exit(1);}

    if(!Serial::SerializeToFile("../"+controllerFolder+"/context.txt",context,SerType::BINARY)){
        exit(1);
    }

    if(!Serial::SerializeToFile("../" + controllerFolder + "/public-key.txt", keyPair.publicKey, SerType::BINARY)){
        exit(1);
    }

    if(!Serial::SerializeToFile("../" + controllerFolder + "/secret-key.txt", keyPair.secretKey, SerType::BINARY)){
        exit(1);
    }

}

void Controller::generateBootstrappingAndRotationKeys(const vector<int>& rotations,
                                                        uint32_t bootstrappingDepth,
                                                        bool serialize,
                                                        const string& filename){



}

void Controller::generateBootstrappingKeys()
{

}

void Controller::generateRotationKeys()
{

}

Ptxt Controller::Encode(const vector<double> &vec,int level,int slot)
{
    Ptxt ptxt= context->MakeCKKSPackedPlaintext(vec,1,level,nullptr,slot);
    ptxt->SetLength(slot);
    return ptxt;
}

Ptxt Controller::Encode(double val, int level, int slot) {
    vector<double> vec;
    for (int i = 0; i < slot; i++) {
        vec.push_back(val);
    }

    Ptxt ptxt = context->MakeCKKSPackedPlaintext(vec, 1, level, nullptr, slot);
    ptxt->SetLength(slot);
    return ptxt;
}

vector<double> Controller::Decode(Ctxt &c,int slot)
{
    Ptxt p;
    context->Decrypt(keyPair.secretKey,c,&p);
    p->SetSlots(slot);
    p->SetLength(slot);
    vector<double> vec = p->GetRealPackedValue();
    return vec;
}

Ctxt Controller::Add(const Ctxt& a, const Ctxt& b)
{
    return context->EvalAdd(a,b);
}

Ctxt Controller::Mul(const Ctxt& a, double b)
{
    Ptxt c=Encode(b,a->GetLevel(),slotNum);
    return context->EvalMult(a,c);
}

Ctxt Controller::Mul(const Ctxt& a, const Ptxt& b)
{
    return context->EvalMult(a,b);
}

Ctxt Controller::bootstrap(const Ctxt& c,bool timing = false)
{
    //所有层数耗尽，开始自举
    if (static_cast<int>(c->GetLevel()) + 2 < circuitDepth && timing) {
        cout << "You are bootstrapping with remaining levels! You are at " << to_string(c->GetLevel()) << "/" << circuitDepth - 2 << endl;
    }

    auto start = begin_time();

    Ctxt res = context->EvalBootstrap(c);

    if (timing) {
        print_duration(start, "Bootstrapping " + to_string(c->GetSlots()) + " slots");
    }

    return res;
}

Ctxt Controller::bootstrap(const Ctxt& c,int precision, bool timing=false)
{
    //考虑精度对自举的影响
    if (static_cast<int>(c->GetLevel()) + 2 < circuitDepth && timing) {
        cout << "You are bootstrapping with remaining levels! You are at " << to_string(c->GetLevel()) << "/" << circuitDepth - 2 << endl;
    }

    auto start = begin_time();

    Ctxt res = context->EvalBootstrap(c,2,precision);

    if (timing) {
        print_duration(start, "Bootstrapping " + to_string(c->GetSlots()) + " slots");
    }
}

Ctxt Controller::relu(const Ctxt& c,double scale,bool timing=false)//切比雪夫近似ReLU
{
    auto start = begin_time();
    //调试过程的解密是不必要的，是可能造成信息泄露的。
    Ctxt res =context->EvalChebyshevFunction([scale](double x) -> double { if (x < 0) return 0; else return (1 / scale) * x; }, c,
                                               -1,
                                               1, relu_degree);
                                               
    if (timing) {
        print_duration(start, "ReLU d = " + to_string(relu_degree) + " evaluation");
    }
    return res;
}

Ctxt Controller::relu_wide(const Ctxt& c,double a, double b, int degree, double scale,bool timing=false)
{
    auto start = begin_time();
    
    Ctxt res =context->EvalChebyshevFunction([scale](double x) -> double { if (x < 0) return 0; else return (1 / scale) * x; }, c,
                                               a,
                                               b, degree);
                                               
    if (timing) {
        print_duration(start, "ReLU d = " + to_string(relu_degree) + " evaluation");
    }
    return res;
}

Ctxt Controller::convbn(const Ctxt &c, int layer, int n,ConvConfig config, double scale = 0.5, bool timing=false)
{
    auto start = begin_time();

    vector<Ctxt> c_rotations;
    int padding=1;

    auto digits = context->EvalFastRotationPrecompute(c);

    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits),-config.img_width));//左上
         
    c_rotations.push_back(
        context->EvalFastRotation(c,-config.img_width,context->GetCyclotomicOrder(),digits));//正上

    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits),-config.img_width));//右上

    c_rotations.push_back(
        context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits));//正左

    c_rotations.push_back(c);//正中

    c_rotations.push_back(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits));//正右

    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits),config.img_width));//左下

    c_rotations.push_back(
        context->EvalFastRotation(c,config.img_width,context->GetCyclotomicOrder(),digits));//正下

    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits),config.img_width));//右下

    Ptxt bias = Encode(read_values_from_file("../weights/layer" + to_string(layer) + "-conv" + to_string(n) + "bn" + to_string(n) + "-bias.bin", scale), c->GetLevel(), 16384);



}

Ptxt Controller::generateMask(int n,int mod,int from,int to,int level,int padding,int pos,double custom_val)
{
    vector<double> mask;

    switch(mod){
    case 0://前n个有效
        for (int i = 0; i < slotNum; i++) {
            if (i < n) {
                mask.push_back(1);
            } else {
                mask.push_back(0);
            }
        }
    case 1://每2n个的前n个有效
        int copy_interval = n;
        for (int i = 0; i < slotNum; i++) {
            if (copy_interval > 0) {
                mask.push_back(1);
            } else {
                mask.push_back(0);
            }

            copy_interval--;

            if (copy_interval <= -n) {
                copy_interval = n;
            }
        }
    case 2://后n个有效
        for (int i = 0; i < slotNum; i++) {
            if (i >= n) {
                mask.push_back(1);
            } else {
                mask.push_back(0);
            }
        }
    case 3://每个块前n*pos个无效，中间n个有效，后续均无效，一个块共padding长，共32块
        for (int i = 0; i < 32; i++) {
            for (int j = 0; j < (pos * n); j++) {
                mask.push_back(0);
            }
            for (int j = 0; j < n; j++) {
                mask.push_back(1);
            }
            for (int j = 0; j < (padding - n - (pos * n)); j++) {
                mask.push_back(0);
            }
        }
    case 4://每个块前n*pos个无效，中间n个有效，后续均无效，一个块共padding长，共64块
        for (int i = 0; i < 64; i++) {
            for (int j = 0; j < (pos * n); j++) {
                mask.push_back(0);
            }
            for (int j = 0; j < n; j++) {
                mask.push_back(1);
            }
            for (int j = 0; j < (padding - n - (pos * n)); j++) {
                mask.push_back(0);
            }
        }
    case 5://共32个块，每个块32*32个数据，前1024*n无效，之后接256个有效，后续均无效
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < 1024; j++) {
                mask.push_back(0);
            }
        }

        for (int i = 0; i < 256; i++) {
            mask.push_back(1);
        }

        for (int i = 0; i < 1024 - 256; i++) {
            mask.push_back(0);
        }

        for (int i = 0; i < 31 - n; i++) {
            for (int j = 0; j < 1024; j++) {
                mask.push_back(0);
            }
        }
    case 6://共64个块，每个块16*16个数据，前256*n无效，之后接64个有效，后续均无效
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < 256; j++) {
                mask.push_back(0);
            }
        }

        for (int i = 0; i < 64; i++) {
            mask.push_back(1);
        }

        for (int i = 0; i < 256 - 64; i++) {
            mask.push_back(0);
        }

        for (int i = 0; i < 63 - n; i++) {
            for (int j = 0; j < 256; j++) {
                mask.push_back(0);
            }
        }
    case 7://每个n个数据进行一次缩放，其他均无效
        for (int i = 0; i < slotNum; i++) {
            if (i % n == 0) {
                mask.push_back(custom_val);
            } else {
                mask.push_back(0);
            }
        } 
    case 8:
        for (int i = 0; i < slotNum; i++) {
        if (i >= from && i < to) {
            mask.push_back(1);
        } else {
            mask.push_back(0);
        }
    }
    }

    return Encode(mask, level, slotNum);
}

 Ctxt Controller::initLayer(const Ctxt& c)//一层convbn一层relu
 {
    Ctxt res;

    return res;
 }

Ctxt Controller::layer1(const Ctxt& c)
{

}

Ctxt Controller::layer2(const Ctxt& c)
{

}

Ctxt Controller::layer3(const Ctxt& c)
{

}

Ctxt Controller::classificationLayer(const Ctxt& c)
{
    
}