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

    ofstream multKey("../"+controllerFolder+"/mult-keys.txt",ios::out|ios::binary);
    if(multKey.is_open()){
        if(!context->SerializeEvalMultKey(multKey,SerType::BINARY)){
            exit(1);
        }
        multKey.close();
    }else{exit(1);}

    if(!Serial::SerializeToFile("../"+controllerFolder+"/crypto-context.txt",context,SerType::BINARY)){
        exit(1);
    }

    if(!Serial::SerializeToFile("../" + controllerFolder + "/public-key.txt", keyPair.publicKey, SerType::BINARY)){
        exit(1);
    }

    if(!Serial::SerializeToFile("../" + controllerFolder + "/secret-key.txt", keyPair.secretKey, SerType::BINARY)){
        exit(1);
    }
}

void Controller::generateContext(int logRing,int logScale,int logPrimes,int digitsHks,int ctsLevels,int stcLevels,int reluDeg,bool serialize)
{
    CCParams<CryptoContextCKKSRNS> params;

    slotNum = 1 << 14;
    relu_degree=reluDeg;

    params.SetBatchSize(slotNum);
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

    ofstream multKey("../"+controllerFolder+"/mult-keys.txt",ios::out|ios::binary);
    if(multKey.is_open()){
        if(!context->SerializeEvalMultKey(multKey,SerType::BINARY)){
            exit(1);
        }
        multKey.close();
    }else{exit(1);}

    if(!Serial::SerializeToFile("../"+controllerFolder+"/crypto-context.txt",context,SerType::BINARY)){
        exit(1);
    }

    if(!Serial::SerializeToFile("../" + controllerFolder + "/public-key.txt", keyPair.publicKey, SerType::BINARY)){
        exit(1);
    }

    if(!Serial::SerializeToFile("../" + controllerFolder + "/secret-key.txt", keyPair.secretKey, SerType::BINARY)){
        exit(1);
    }

}

void Controller::loadContext(bool verbose)
{
    context->ClearEvalMultKeys();
    context->ClearEvalAutomorphismKeys();

    CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

     if (!Serial::DeserializeFromFile("../" + controllerFolder + "/crypto-context.txt", context, SerType::BINARY)) {
        cerr << "I cannot read serialized data from: " << "../" + controllerFolder + "/crypto-context.txt" << endl;
        exit(1);
    }

    PublicKey<DCRTPoly> clientPublicKey;
    if (!Serial::DeserializeFromFile("../" + controllerFolder + "/public-key.txt", clientPublicKey, SerType::BINARY)) {
        cerr << "I cannot read serialized data from public-key.txt" << endl;
        exit(1);
    }

    PrivateKey<DCRTPoly> serverSecretKey;
    if (!Serial::DeserializeFromFile("../" + controllerFolder + "/secret-key.txt", serverSecretKey, SerType::BINARY)) {
        cerr << "I cannot read serialized data from public-key.txt" << endl;
        exit(1);
    }

    keyPair.publicKey = clientPublicKey;
    keyPair.secretKey = serverSecretKey;

    std::ifstream multKeyIStream("../" + controllerFolder + "/mult-keys.txt", ios::in | ios::binary);
    if (!multKeyIStream.is_open()) {
        cerr << "Cannot read serialization from " << "mult-keys.txt" << endl;
        exit(1);
    }
    if (!context->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
        cerr << "Could not deserialize eval mult key file" << endl;
        exit(1);
    }

    relu_degree = stoi(read_first_line("../" + controllerFolder + "/relu_degree.txt"));

    level_budget[0] = read_first_line("../" + controllerFolder + "/level_budget.txt").at(0) - '0';
    level_budget[1] = read_first_line("../" + controllerFolder + "/level_budget.txt").at(2) - '0';

    if (verbose) cout << "CtoS: " << level_budget[0] << ", StoC: " << level_budget[1] << endl;

    uint32_t approxBootstrapDepth = 4 + 4;  

    uint32_t levelsUsedBeforeBootstrap = relu_depth[relu_degree] + 3;

    circuitDepth = levelsUsedBeforeBootstrap + FHECKKSRNS::GetBootstrapDepth(approxBootstrapDepth, level_budget, SPARSE_TERNARY);

    if (verbose) cout << "Circuit depth: " << circuitDepth << ", available multiplications: " << levelsUsedBeforeBootstrap - 2 << endl;

    slotNum = 1 << 14;
}

void Controller::generateBootstrappingAndRotationKeys(const vector<int>& rotations,
                                                        uint32_t bootstrappingDepth,
                                                        bool serialize,
                                                        const string& filename)
{
        if (serialize && filename.empty()) {return;}
    generateBootstrappingKeys(bootstrappingDepth);
    generateRotationKeys(rotations, serialize, filename);
    return;
}

void Controller::generateBootstrappingKeys(int bootstrap_slots)
{

    context->EvalBootstrapSetup(level_budget, {0, 0}, bootstrap_slots);
    context->EvalBootstrapKeyGen(keyPair.secretKey,bootstrap_slots);
    return;
}

void Controller::generateRotationKeys(const vector<int>& rotations, bool serialize,string filename)
{
    if (serialize && filename.size() == 0) {return;}

    context->EvalRotateKeyGen(keyPair.secretKey, rotations);

    if (serialize) {
        ofstream rotationKeyFile("../" + controllerFolder + "/rot_" + filename, ios::out | ios::binary);
        if (rotationKeyFile.is_open()) {
            if (!context->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::BINARY)) {
                cerr << "Error writing rotation keys" << endl;
                exit(1);
            }
            cout << "Rotation keys \"" << filename << "\" have been serialized" << endl;
        } else {
            cerr << "Error serializing Rotation keys" << "../" + controllerFolder + "/rot_" + filename << endl;
            exit(1);
        }
    }
}

void Controller::load_bootstrapping_and_rotation_keys(const string& filename, int bootstrap_slots)
{
    auto start = begin_time();

    context->EvalBootstrapSetup(level_budget, {0, 0}, bootstrap_slots);

    ifstream rotKeyIStream("../" + controllerFolder + "/rot_" + filename, ios::in | ios::binary);
    if (!rotKeyIStream.is_open()) {
        cerr << "Cannot read serialization from " << "../" + controllerFolder + "/" << "rot_" << filename << std::endl;
        exit(1);
    }

    if (!context->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
        cerr << "Could not deserialize eval rot key file" << std::endl;
        exit(1);
    }

    print_duration(start, "Loading bootstrapping pre-computations + rotations");
    cout << endl;
}

void Controller::load_rotation_keys(const string& filename)
{
    auto start = begin_time();

    ifstream rotKeyIStream("../" + controllerFolder + "/rot_" + filename, ios::in | ios::binary);
    if (!rotKeyIStream.is_open()) {
        cerr << "Cannot read serialization from " << "../" + controllerFolder + "/" << "rot_" << filename << std::endl;
        exit(1);
    }

    if (!context->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
        cerr << "Could not deserialize eval rot key file" << std::endl;
        exit(1);
    }

    print_duration(start, "Loading rotation keys");
}

void Controller::clear_keys() {
    context->ClearEvalAutomorphismKeys();
}

void Controller::clear_context() {
    clear_keys();
    context->ClearEvalMultKeys();
}

Ptxt Controller::Encode(const vector<double> &vec,int level,int slot)
{
    if (slot == 0) {
        slot = slotNum;
    }

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

Ctxt Controller::Encrypt(const Ptxt& p)
{
    return context->Encrypt(p,keyPair.publicKey);
}

Ptxt Controller::Decrypt(const Ctxt& c)
{
    Ptxt p;
    context->Decrypt(keyPair.secretKey,c,&p);
    return p;
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

Ctxt Controller::bootstrap(const Ctxt& c,bool timing)
{
    //层数耗尽，开始自举
    if (static_cast<int>(c->GetLevel()) + 2 < circuitDepth && timing) {
        cout << "You are bootstrapping with remaining levels! You are at " << to_string(c->GetLevel()) << "/" << circuitDepth - 2 << endl;
        return c;//存在大量层数为什么还要自举？
    }

    auto start = begin_time();

    Ctxt res = context->EvalBootstrap(c);

    if (timing) {
        print_duration(start, "Bootstrapping " + to_string(c->GetSlots()) + " slots");
    }

    return res;
}

Ctxt Controller::bootstrap(const Ctxt& c,int precision, bool timing)
{
    //考虑精度对自举的影响
    if (static_cast<int>(c->GetLevel()) + 2 < circuitDepth && timing) {
        cout << "You are bootstrapping with remaining levels! You are at " << to_string(c->GetLevel()) << "/" << circuitDepth - 2 << endl;
        return c;
    }

    auto start = begin_time();

    Ctxt res = context->EvalBootstrap(c,2,precision);

    if (timing) {
        print_duration(start, "Bootstrapping " + to_string(c->GetSlots()) + " slots");
    }

    return res;
}

Ctxt Controller::relu(const Ctxt& c,double scale,bool timing)//切比雪夫近似ReLU
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

Ctxt Controller::relu_wide(const Ctxt& c,double a, double b, int degree, double scale,bool timing)
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

Ctxt Controller::convbn_initial(const Ctxt &c,double scale, bool timing)
{
    auto start = begin_time();

    vector<Ctxt> c_rotations;
    int padding=1;
    int img_width=32;

    auto digits = context->EvalFastRotationPrecompute(c);

    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits),-img_width));//左上
    c_rotations.push_back(
        context->EvalFastRotation(c,-img_width,context->GetCyclotomicOrder(),digits));//正上
    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits),-img_width));//右上
    c_rotations.push_back(
        context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits));//正左
    c_rotations.push_back(c);//正中
    c_rotations.push_back(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits));//正右
    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits),img_width));//左下
    c_rotations.push_back(
        context->EvalFastRotation(c,img_width,context->GetCyclotomicOrder(),digits));//正下
    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits),img_width));//右下

    Ptxt bias = Encode(read_from_file("../weights/conv1bn1-bias.bin", scale), c->GetLevel(), 16384);

    Ctxt finalsum;

    generateRotationKeys({1024});

    for (int j = 0; j < 16; j++) {
        vector<Ctxt> k_rows;

        for (int k = 0; k < 9; k++) {
            vector<double> values = read_from_file("../weights/conv1bn1-ch" +
                                                          to_string(j) + "-k" + to_string(k+1) + ".bin", scale);
            Ptxt encoded = Encode(values, c->GetLevel(), 16384);
            k_rows.push_back(context->EvalMult(c_rotations[k], encoded));
        }

        Ctxt sum = context->EvalAddMany(k_rows);

        Ctxt res = sum->Clone();

        res = Add(res, context->EvalRotate(sum, 1024));
        res = Add(res, context->EvalRotate(context->EvalRotate(sum, 1024), 1024));

        //掩码问题1
        MaskConfig mask_config;
        mask_config.type = MaskType::RANGE;
        mask_config.from = 0;
        mask_config.to = 1024;

        res = Mul(res, generateMask(0, res->GetLevel(), mask_config,0));


        if (j == 0) {
            finalsum = res->Clone();
            finalsum = context->EvalRotate(finalsum, 1024);
        } else {
            finalsum = context->EvalAdd(finalsum, res);
            finalsum = context->EvalRotate(finalsum, 1024);
        }

    }

    finalsum = context->EvalAdd(finalsum, bias);

    if (timing) {
        print_duration(start, "Initial layer");
    }

    return finalsum;
}

Ctxt Controller::convbn(const Ctxt &c, int layer, int n,ConvConfig config, double scale , bool timing)
{
    auto start = begin_time();

    vector<Ctxt> c_rotations;
    int padding=1;

    auto digits = context->EvalFastRotationPrecompute(c);

    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits),-config.img_width));
    c_rotations.push_back(
        context->EvalFastRotation(c,-config.img_width,context->GetCyclotomicOrder(),digits));
    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits),-config.img_width));
    c_rotations.push_back(
        context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits));
    c_rotations.push_back(c);
    c_rotations.push_back(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits));
    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits),config.img_width));
    c_rotations.push_back(
        context->EvalFastRotation(c,config.img_width,context->GetCyclotomicOrder(),digits));
    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits),config.img_width));

    Ptxt bias = Encode(read_from_file("../weights/layer" + to_string(layer) + "-conv" + to_string(n) + "bn" + to_string(n) + "-bias.bin", scale), c->GetLevel(), config.slot);

    Ctxt finalsum;

    for (int j = 0; j < config.num_channels; j++) {
        vector<Ctxt> k_rows;

        for (int k = 0; k < 9; k++) {
            vector<double> values = read_from_file("../weights/layer" + to_string(layer) + "-conv" + to_string(n) + "bn" + to_string(n) + "-ch" +
                                                          to_string(j) + "-k" + to_string(k+1) + ".bin", scale);
            Ptxt encoded = Encode(values, c->GetLevel(), config.slot);//关于convbn2，原作者使用了cirrcuit_depth-2的固定长度，但我们不去管他
            k_rows.push_back(context->EvalMult(c_rotations[k], encoded));
        }

        Ctxt sum = context->EvalAddMany(k_rows);

        if (j == 0) {
            finalsum = sum->Clone();
            finalsum = context->EvalRotate(finalsum, -config.img_size);
        } else {
            finalsum = context->EvalAdd(finalsum, sum);
            finalsum = context->EvalRotate(finalsum, -config.img_size);
        }

    }

    finalsum = context->EvalAdd(finalsum, bias);

    if (timing) {
        print_duration(start, "Block " + to_string(layer) + " - convbn" + to_string(n));
    }

    return finalsum;
}

vector<Ctxt> Controller::convbnSx(const Ctxt &c, int layer, int n,ConvConfig config, double scale, bool timing)
{
     auto start = begin_time();

    vector<Ctxt> c_rotations;
    int padding=1;

    auto digits = context->EvalFastRotationPrecompute(c);

    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits),-config.img_width));
    c_rotations.push_back(
        context->EvalFastRotation(c,-config.img_width,context->GetCyclotomicOrder(),digits));
    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits),-config.img_width));
    c_rotations.push_back(
        context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits));
    c_rotations.push_back(c);
    c_rotations.push_back(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits));
    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,-padding,context->GetCyclotomicOrder(),digits),config.img_width));
    c_rotations.push_back(
        context->EvalFastRotation(c,config.img_width,context->GetCyclotomicOrder(),digits));
    c_rotations.push_back(
        context->EvalRotate(
            context->EvalFastRotation(c,padding,context->GetCyclotomicOrder(),digits),config.img_width));

    Ptxt bias1 = Encode(read_from_file("../weights/layer" + to_string(layer) + "-conv" + to_string(n) + "bn" + to_string(n) + "-bias1.bin", scale), c->GetLevel(), config.slot);
    Ptxt bias2 = Encode(read_from_file("../weights/layer" + to_string(layer) + "-conv" + to_string(n) + "bn" + to_string(n) + "-bias2.bin", scale), c->GetLevel(), config.slot);

    Ctxt finalsum1,finalsum2;

    for (int j = 0; j < config.num_channels; j++) {
        vector<Ctxt> k_rows1,k_rows2;

        for (int k = 0; k < 9; k++) {
            vector<double> values = read_from_file("../weights/layer" + to_string(layer) + "-conv" + to_string(n) + "bn" + to_string(n) + "-ch" +
                                                          to_string(j) + "-k" + to_string(k+1) + ".bin", scale);
            Ptxt encoded = Encode(values, c->GetLevel(), config.slot);
            k_rows1.push_back(context->EvalMult(c_rotations[k], encoded));

            values = read_from_file("../weights/layer" + to_string(layer) + "-conv" + to_string(n) + "bn" + to_string(n) + "-ch" +
                                                          to_string(j+config.num_channels) + "-k" + to_string(k+1) + ".bin", scale);
            encoded = Encode(values, c->GetLevel(), config.slot);
            k_rows2.push_back(context->EvalMult(c_rotations[k], encoded));
        }

        Ctxt sum1 = context->EvalAddMany(k_rows1);
        Ctxt sum2 = context->EvalAddMany(k_rows2);

        if (j == 0) {
            finalsum1 = sum1->Clone();
            finalsum1 = context->EvalRotate(finalsum1, -config.img_size);
            finalsum2 = sum2->Clone();
            finalsum2 = context->EvalRotate(finalsum2, -config.img_size);
        } else {
            finalsum1 = context->EvalAdd(finalsum1, sum1);
            finalsum1 = context->EvalRotate(finalsum1, -config.img_size);
            finalsum2 = context->EvalAdd(finalsum2, sum2);
            finalsum2 = context->EvalRotate(finalsum2, -config.img_size);
        }

    }

    finalsum1 = context->EvalAdd(finalsum1, bias1);
    finalsum2 = context->EvalAdd(finalsum2, bias2);

    if (timing) {
        print_duration(start, "Block " + to_string(layer) + " - convbnSx" + to_string(n));
    }

    return {finalsum1,finalsum2};
}

vector<Ctxt> Controller::convbnDx(const Ctxt &c, int layer, int n,ConvConfig config, double scale, bool timing)
{
    auto start = begin_time();

    Ptxt bias1 = Encode(read_from_file("../weights/layer" + to_string(layer) + "dx-conv" + to_string(n) + "bn" + to_string(n) + "-bias1.bin", scale), c->GetLevel(), config.slot);
    Ptxt bias2 = Encode(read_from_file("../weights/layer" + to_string(layer) + "dx-conv" + to_string(n) + "bn" + to_string(n) + "-bias2.bin", scale), c->GetLevel(), config.slot);

    Ctxt finalsum1,finalsum2;

    for (int j = 0; j < config.num_channels; j++) {
        vector<Ctxt> k_rows1,k_rows2;

        vector<double> values = read_from_file("../weights/layer" + to_string(layer) + "-conv" + to_string(n) + "bn" + to_string(n) + "-ch" +
                                                        to_string(j) + "-k" + to_string(1) + ".bin", scale);
        Ptxt encoded = Encode(values, c->GetLevel(), config.slot);
        k_rows1.push_back(context->EvalMult(c, encoded));

        values = read_from_file("../weights/layer" + to_string(layer) + "-conv" + to_string(n) + "bn" + to_string(n) + "-ch" +
                                        to_string(j+config.num_channels) + "-k" + to_string(1) + ".bin", scale);
        encoded = Encode(values, c->GetLevel(), config.slot);
        k_rows2.push_back(context->EvalMult(c, encoded));

        Ctxt sum1 = context->EvalAddMany(k_rows1);
        Ctxt sum2 = context->EvalAddMany(k_rows2);

        if (j == 0) {
            finalsum1 = sum1->Clone();
            finalsum1 = context->EvalRotate(finalsum1, -config.img_size);
            finalsum2 = sum2->Clone();
            finalsum2 = context->EvalRotate(finalsum2, -config.img_size);
        } else {
            finalsum1 = context->EvalAdd(finalsum1, sum1);
            finalsum1 = context->EvalRotate(finalsum1, -config.img_size);
            finalsum2 = context->EvalAdd(finalsum2, sum2);
            finalsum2 = context->EvalRotate(finalsum2, -config.img_size);
        }

    }

    finalsum1 = context->EvalAdd(finalsum1, bias1);
    finalsum2 = context->EvalAdd(finalsum2, bias2);

    if (timing) {
        print_duration(start, "Block " + to_string(layer) + " - convbnDx" + to_string(n));
    }

    return {finalsum1,finalsum2};
}


Ctxt Controller::downsample1024to256(const Ctxt &c1, const Ctxt &c2)
{
    c1->SetSlots(32768);
    c2->SetSlots(32768);
    slotNum = 16384*2;

    MaskConfig config1,config2;
    config1.type = MaskType::FIRST_N;
    config2.type = MaskType::LAST_N;

    //c1的前半段和c2的后半段相加，综合成一个ctxt
    Ctxt fullpack=Add(Mul(c1, generateMask(16384, c1->GetLevel(), config1, 0.0)), Mul(c2, generateMask(16384, c2->GetLevel(), config2, 0.0)));

    MaskConfig temp;
    temp.type=MaskType::FIRST_N_OF_EVERY_2N;
    fullpack = context->EvalMult(context->EvalAdd(fullpack, context->EvalRotate(fullpack, 1)), generateMask(2, fullpack->GetLevel(),temp,0));
    fullpack = context->EvalMult(context->EvalAdd(fullpack, context->EvalRotate(context->EvalRotate(fullpack, 1), 1)), generateMask(4, fullpack->GetLevel(),temp,0));
    fullpack = context->EvalMult(context->EvalAdd(fullpack, context->EvalRotate(fullpack, 4)), generateMask(8, fullpack->GetLevel(),temp,0));
    fullpack = context->EvalAdd(fullpack, context->EvalRotate(fullpack, 8));

    Ctxt downsampledrows = Encrypt(Encode({0}));

    for (int i = 0; i < 16; i++) {
        temp.type=MaskType::PER_BLOCK_SLICE_32;
        temp.padding=1024;
        temp.pos=i;

        Ctxt masked = context->EvalMult(fullpack, generateMask(16,fullpack->GetLevel(),temp,0));
        downsampledrows = context->EvalAdd(downsampledrows, masked);
        if (i < 15) {
            fullpack = context->EvalRotate(fullpack, 64 - 16); 
        }
    }

    Ctxt downsampledchannels = Encrypt(Encode({0}));

    for (int i = 0; i < 32; i++) {
        temp.type=MaskType::SKIP_N_BLOCKS_THEN_256_32;
        Ctxt masked = context->EvalMult(downsampledrows, generateMask(i, downsampledrows->GetLevel(),temp,0));
        downsampledchannels = context->EvalAdd(downsampledchannels, masked);
        downsampledchannels = context->EvalRotate(downsampledchannels, -(1024 - 256));
    }

    downsampledchannels = context->EvalRotate(downsampledchannels, (1024 - 256) * 32);
    downsampledchannels = context->EvalAdd(downsampledchannels, context->EvalRotate(downsampledchannels, -8192));
    downsampledchannels = context->EvalAdd(downsampledchannels, context->EvalRotate(context->EvalRotate(downsampledchannels, -8192), -8192));

    downsampledchannels->SetSlots(8192);

    return downsampledchannels;

}


Ctxt Controller::downsample256to64(const Ctxt &c1, const Ctxt &c2) {
    c1->SetSlots(16384);
    c2->SetSlots(16384);
    slotNum = 8192*2;

    MaskConfig config1,config2;
    config1.type = MaskType::FIRST_N;
    config2.type = MaskType::LAST_N;

    Ctxt fullpack = Add(Mul(c1, generateMask(8192, c1->GetLevel(), config1, 0.0)), Mul(c2, generateMask(8192, c2->GetLevel(), config2, 0.0)));

    MaskConfig temp;
    temp.type=MaskType::FIRST_N_OF_EVERY_2N;
    fullpack = context->EvalMult(context->EvalAdd(fullpack, context->EvalRotate(fullpack, 1)), generateMask(2, fullpack->GetLevel(),temp,0));
    fullpack = context->EvalMult(context->EvalAdd(fullpack, context->EvalRotate(context->EvalRotate(fullpack, 1), 1)), generateMask(4, fullpack->GetLevel(),temp,0));
    fullpack = context->EvalAdd(fullpack, context->EvalRotate(fullpack, 4));

    Ctxt downsampledrows = Encrypt(Encode({0}));

    for (int i = 0; i < 32; i++) {
        temp.type=MaskType::PER_BLOCK_SLICE_64;
        temp.padding=256;
        temp.pos=i;
        Ctxt masked = context->EvalMult(fullpack, generateMask(8,fullpack->GetLevel(),temp,0));
        downsampledrows = context->EvalAdd(downsampledrows, masked);
        if (i < 31) {
            fullpack = context->EvalRotate(fullpack, 32 - 8);
        }
    }

    Ctxt downsampledchannels = Encrypt(Encode({0}));
    for (int i = 0; i < 64; i++) {
        temp.type=MaskType::SKIP_N_BLOCKS_THEN_64_64;
        Ctxt masked = context->EvalMult(downsampledrows, generateMask(i, downsampledrows->GetLevel(),temp,0));
        downsampledchannels = context->EvalAdd(downsampledchannels, masked);
        downsampledchannels = context->EvalRotate(downsampledchannels, -(256 - 64));
    }

    downsampledchannels = context->EvalRotate(downsampledchannels, (256 - 64) * 64);
    downsampledchannels = context->EvalAdd(downsampledchannels, context->EvalRotate(downsampledchannels, -4096));
    downsampledchannels = context->EvalAdd(downsampledchannels, context->EvalRotate(context->EvalRotate(downsampledchannels, -4096), -4096));

    downsampledchannels->SetSlots(4096);

    return downsampledchannels;

}

Ctxt Controller::rotsum(const Ctxt &in, int slots) {
    Ctxt result = in->Clone();

    for (int i = 0; i < log2(slots); i++) {
        result = Add(result, context->EvalRotate(result, pow(2, i)));
    }

    return result;
}

Ctxt Controller::rotsum_padded(const Ctxt &in, int slots) {
    Ctxt result = in->Clone();

    for (int i = 0; i < log2(slots); i++) {
        result = Add(result, context->EvalRotate(result, slots * pow(2, i)));
    }

    return result;
}

Ctxt Controller::repeat(const Ctxt &in, int slots) {
    return context->EvalRotate(rotsum(in, slots), -slots + 1);
}


Ptxt Controller::generateMask(int n,int level,MaskConfig config,double custom_val)
{
    vector<double> mask;

    switch(config.type){
    case MaskType::FIRST_N://前n个有效
        {
            for (int i = 0; i < slotNum; i++) {
                if (i < n) {
                    mask.push_back(1);
                } else {
                    mask.push_back(0);
                }
            }
            return Encode(mask, level, slotNum);
        }
    case MaskType::LAST_N://后n个有效
        {
            for (int i = 0; i < slotNum; i++) {
                if (i >= n) {
                    mask.push_back(1);
                } else {
                    mask.push_back(0);
                }
            }
            return Encode(mask, level, slotNum);
        }
    case MaskType::FIRST_N_OF_EVERY_2N://每2n个的前n个有效
        {
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
            return Encode(mask, level, slotNum);
        }
    case MaskType::PER_BLOCK_SLICE_32://每个块前n*pos个无效，中间n个有效，后续均无效，一个块共padding长，共32块
        {
            for (int i = 0; i < 32; i++) {
                for (int j = 0; j < (config.pos * n); j++) {
                    mask.push_back(0);
                }
                for (int j = 0; j < n; j++) {
                    mask.push_back(1);
                }
                for (int j = 0; j < (config.padding - n - (config.pos * n)); j++) {
                    mask.push_back(0);
                }
            }
            return Encode(mask, level, 16384 * 2);
        }
    case MaskType::PER_BLOCK_SLICE_64://每个块前n*pos个无效，中间n个有效，后续均无效，一个块共padding长，共64块
        {
            for (int i = 0; i < 64; i++) {
                for (int j = 0; j < (config.pos * n); j++) {
                    mask.push_back(0);
                }
                for (int j = 0; j < n; j++) {
                    mask.push_back(1);
                }
                for (int j = 0; j < (config.padding - n - (config.pos * n)); j++) {
                    mask.push_back(0);
                }
            }
            return Encode(mask, level, 8192 * 2);
        }
    case MaskType::SKIP_N_BLOCKS_THEN_256_32://共32个块，每个块32*32个数据，前1024*n无效，之后接256个有效，后续均无效
        {
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
            return Encode(mask, level, 16384 * 2);
        }
    case MaskType::SKIP_N_BLOCKS_THEN_64_64://共64个块，每个块16*16个数据，前256*n无效，之后接64个有效，后续均无效
        {
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
            return Encode(mask, level, 8192 * 2);
        }
    case MaskType::EVERY_NTH://每个n个数据进行一次缩放，其他均无效
        {
            for (int i = 0; i < slotNum; i++) {
                if (i % n == 0) {
                    mask.push_back(custom_val);
                } else {
                    mask.push_back(0);
                }
            } 
            return Encode(mask, level, slotNum);
        }
    case MaskType::RANGE://从from到to有效
        {
            for (int i = 0; i < slotNum; i++) {
                if (i >= config.from && i < config.to) {
                    mask.push_back(1);
                } else {
                    mask.push_back(0);
                }
            }
            return Encode(mask, level, slotNum);
        }
    }
    return Encode({0});
}

 Ctxt Controller::initLayer(const Ctxt& c, int verbose)//一层convbn一层relu
 {
    double scale = 0.90;
        
    Ctxt res=convbn_initial(c, scale, verbose > 1);
    res=relu(res, scale, verbose > 1);

    return res;
 }

Ctxt Controller::layer1(const Ctxt& c, int verbose)//三层basicblock
{
    double scale=1.0;

    auto start = begin_time();

    ConvConfig config;
    config.img_width=32;
    config.img_size=1024;
    config.num_channels=16;
    config.slot=16384;

    Ctxt res1=c->Clone(),res2,res3;

    res1=convbn(res1,1,1, config, scale, verbose > 1);
    res1=bootstrap(res1);
    res1=relu(res1, scale, verbose > 1);

    scale = 0.52;

    res1=convbn(res1,1,2, config, scale, verbose > 1);
    res1=Add(res1,Mul(c,scale));
    res1=bootstrap(res1,verbose>1);
    res1=relu(res1, scale, verbose > 1);

    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer1 - Block 1---" << endl;

    scale = 0.55;

    start = begin_time();
    res2=convbn(res1,2,1, config, scale, verbose > 1);
    res2=bootstrap(res2);
    res2=relu(res2, scale, verbose > 1);

    scale = 0.36;

    res2=convbn(res2,2,2, config, scale, verbose > 1);
    res2=Add(res2,Mul(res1,scale));
    res2=bootstrap(res2,verbose>1);
    res2=relu(res2, scale, verbose > 1);

    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer1 - Block 2---" << endl;

    scale = 0.63;

    start = begin_time();
    res3=convbn(res2,3,1, config, scale, verbose > 1);
    res3=bootstrap(res3);
    res3=relu(res3, scale, verbose > 1);

    scale = 0.42;

    res3=convbn(res3,3,2, config, scale, verbose > 1);
    res3=Add(res3,Mul(res2,scale));
    res3=bootstrap(res3,verbose>1);
    res3=relu(res3, scale, verbose > 1);

    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer1 - Block 2---" << endl;

    return res3;
}

Ctxt Controller::layer2(const Ctxt& c, int verbose)//一层下采样，两层basicblock
{

    double scaleSx = 0.57;
    double scaleDx = 0.40;


    bool timing = verbose > 1;

    if (verbose > 1) cout << "---Start: Layer2 - Block 1---" << endl;
    auto start = begin_time();
    Ctxt boot_in = bootstrap(c, timing);

    ConvConfig config;
    config.img_width=32;
    config.img_size=1024;
    config.num_channels=16;
    config.slot=16384;

    vector<Ctxt> res1sx = convbnSx(boot_in, 4, 1,config, scaleSx, timing); 

    vector<Ctxt> res1dx = convbnDx(boot_in, 4, 1,config, scaleDx, timing); 

    clear_keys();
    load_rotation_keys("rotations-layer2-downsample.bin");

    Ctxt fullpackSx = downsample1024to256(res1sx[0], res1sx[1]);
    Ctxt fullpackDx = downsample1024to256(res1dx[0], res1dx[1]);

    res1sx.clear();
    res1dx.clear();

    clear_keys();
    load_bootstrapping_and_rotation_keys("rotations-layer2.bin", 8192);

    slotNum = 8192;
    fullpackSx = bootstrap(fullpackSx, timing);

    fullpackSx = relu(fullpackSx, scaleSx, timing);

    ConvConfig config2;
    config2.img_width=16;
    config2.img_size=256;
    config2.slot=8192;
    config2.num_channels=32;

    fullpackSx = convbn(fullpackSx, 4, 2, config2, scaleDx, timing);//使用右分支

    Ctxt res1 = Add(fullpackSx, fullpackDx);
    res1 = bootstrap(res1, timing);
    res1 = relu(res1, scaleDx, timing);

    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer2 - Block 1---" << endl;//下采样结束

    double scale = 0.76;

    if (verbose > 1) cout << "---Start: Layer2 - Block 2---" << endl;
    start = begin_time();

    Ctxt res2;
    res2 = convbn(res1, 5, 1, config2, scale, timing);
    res2 = bootstrap(res2, timing);
    res2 = relu(res2, scale, timing);

    scale = 0.37;

    res2 = convbn(res2, 5, 2, config2, scale, timing);
    res2 = Add(res2, Mul(res1, scale));
    res2 = bootstrap(res2, timing);
    res2 = relu(res2, scale, timing);
    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer2 - Block 2---" << endl;

    scale = 0.63;

    if (verbose > 1) cout << "---Start: Layer2 - Block 3---" << endl;
    start = begin_time();
    Ctxt res3;
    res3 = convbn(res2, 6, 1, config2, scale, timing);
    res3 = bootstrap(res3, timing);
    res3 = relu(res3, scale, timing);
  
    scale = 0.25;

    res3 = convbn(res3, 6, 2, config2, scale, timing);
    res3 = Add(res3, Mul(res2, scale));
    res3 = bootstrap(res3, timing);
    res3 = relu(res3, scale, timing);
    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer2 - Block 3---" << endl;

    return res3;
}

Ctxt Controller::layer3(const Ctxt& c, int verbose)
{
    double scaleSx = 0.63;
    double scaleDx = 0.40;

    bool timing = verbose > 1;

    if (verbose > 1) cout << "---Start: Layer3 - Block 1---" << endl;
    auto start = begin_time();
    Ctxt boot_in = bootstrap(c, timing);

    ConvConfig config;
    config.img_width=16;
    config.img_size=256;
    config.num_channels=32;
    config.slot=8192;

    vector<Ctxt> res1sx = convbnSx(boot_in, 7, 1,config, scaleSx, timing); 

    vector<Ctxt> res1dx = convbnDx(boot_in, 7, 1,config, scaleDx, timing);

    clear_keys();
    load_rotation_keys("rotations-layer3-downsample.bin");

    Ctxt fullpackSx = downsample256to64(res1sx[0], res1sx[1]);
    Ctxt fullpackDx = downsample256to64(res1dx[0], res1dx[1]);
    res1sx.clear();
    res1dx.clear();

    clear_keys();
    load_bootstrapping_and_rotation_keys("rotations-layer3.bin", 4096);

    slotNum = 4096;
    fullpackSx = bootstrap(fullpackSx, timing);

    fullpackSx = relu(fullpackSx, scaleSx, timing);

    ConvConfig config2;
    config2.img_width=8;
    config2.img_size=64;
    config2.slot=4096;
    config2.num_channels=64;

    fullpackSx = convbn(fullpackSx, 7, 2, config2, scaleDx, timing);

    Ctxt res1 = Add(fullpackSx, fullpackDx);
    res1 = bootstrap(res1, timing);
    res1 = relu(res1, scaleDx, timing);

    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer3 - Block 1---" << endl;

    double scale = 0.57;

    if (verbose > 1) cout << "---Start: Layer3 - Block 2---" << endl;
    start = begin_time();
    Ctxt res2;
    res2 = convbn(res1, 8, 1, config2, scale, timing);
    res2 = bootstrap(res2, timing);
    res2 = relu(res2, scale, timing);

    scale = 0.33;

    res2 = convbn(res2, 8, 2, config2, scale, timing);
    res2 = Add(res2, Mul(res1, scale));
    res2 = bootstrap(res2, timing);
    res2 = relu(res2, scale, timing);

    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer3 - Block 2---" << endl;

    scale = 0.69;

    if (verbose > 1) cout << "---Start: Layer3 - Block 3---" << endl;
    start = begin_time();
    Ctxt res3;

    res3 = convbn(res2, 9, 1, config2, scale, timing);
    res3 = bootstrap(res3, timing);
    res3 = relu(res3, scale, timing);

    scale = 0.1;

    res3 = convbn(res3, 9, 2, config2, scale, timing);
    res3 = Add(res3, Mul(res2, scale));
    res3 = bootstrap(res3, timing);
    res3 = relu(res3, scale, timing);
    res3 = bootstrap(res3, timing);

    if (verbose > 1) print_duration(start, "Total");
    if (verbose > 1) cout << "---End  : Layer3 - Block 3---" << endl;


    return res3;
}

Ctxt Controller::classificationLayer(const Ctxt& c,string input_filename,int verbose)
{
    clear_keys();
    load_rotation_keys("rotations-finallayer.bin");

    slotNum=4096;
    Ptxt weight = Encode(read_fc_weight(), c->GetLevel(), slotNum); 

    Ctxt res = rotsum(c, 64);

    MaskConfig config;
    config.type=MaskType::EVERY_NTH;
    res = Mul(res, generateMask(64, res->GetLevel(),config, 1.0 / 64.0));

    res = repeat(res, 16);
    res = Mul(res, weight);
    res = rotsum_padded(res, 64);

    if (verbose >= 0) {
        cout << "Decrypting the output..." << endl;
        print(res, 10, "Output: ");
    }


    vector<double> clear_result = Decode(res, 10);

    auto max_element_iterator = std::max_element(clear_result.begin(), clear_result.end());
    int index_max = distance(clear_result.begin(), max_element_iterator);

    if (verbose >= 0) {
        cout << "The input image is classified as " << YELLOW_TEXT << tools::class_map[index_max] << RESET_COLOR << "" << endl;
        cout << "The index of max element is " << YELLOW_TEXT << index_max << RESET_COLOR << "" << endl;  
        
        // string command = "python3 ../src/plain/script.py \"" + input_filename + "\"";
        // int return_sys = system(command.c_str());
        // if (return_sys == 1) {
        //     cout << "There was an error launching src/plain/script.py. Run it from Python in order to debug it." << endl;
        // }
    }

    return res;
}


void Controller::print(const Ctxt& c, int slots, string prefix)
{
    if (slots == 0) {
        slots = slotNum;
    }

    cout << prefix;

    Ptxt result;
    context->Decrypt(keyPair.secretKey, c, &result);
    result->SetSlots(slotNum);
    vector<double> v = result->GetRealPackedValue();

    cout << setprecision(3) << fixed;
    cout << "[ ";

    for (int i = 0; i < slots; i += 1) {
        string segno = "";
        if (v[i] > 0) {
            segno = " ";
        } else {
            segno = "-";//避免负数
            v[i] = -v[i];
        }


        if (i == slots - 1) {
            cout << segno << v[i] << " ]";
        } else {
            if (abs(v[i]) < 0.00000001)
                cout << " 0.0000000000" << ", ";
            else
                cout << segno << v[i] << ", ";
        }
    }

    cout << endl;
}

void Controller::bootstrap_precision(const Ctxt &c) {
    cout << "Computing boostrap precision..." << endl;

    Ptxt a = Decrypt(c);
    Ptxt b = Decrypt(bootstrap(c));

    cout << "Precision: " << to_string(tools::compute_approx_error(a, b)) << endl;
}