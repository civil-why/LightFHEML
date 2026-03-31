#ifndef FHECONTROLLER_H
#define FHECONTROLLER_H

#include "openfhe.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include <thread>

#include "Tools.h"

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;

using namespace tools;

using Ptxt = Plaintext;
using Ctxt = Ciphertext<DCRTPoly>;

struct ConvConfig{
    int img_width;          //输入图像宽度，layer1为32，layer2为16，layer3为8
    int img_size;           //输入图像大小，layer1为1024，layer2为256，layer3为64
    int num_channels;       //输入图像通道数，layer1为16，layer2为32，layer3为64
    int slot;               //slot数量，layer1为16384，layer2为8192，layer3为4096
};

enum class MaskType{FIRST_N,
    LAST_N,
    FIRST_N_OF_EVERY_2N,
    PER_BLOCK_SLICE_32,
    PER_BLOCK_SLICE_64,
    SKIP_N_BLOCKS_THEN_256_32,
    SKIP_N_BLOCKS_THEN_64_64,
    EVERY_NTH,
    RANGE};

struct MaskConfig{
    MaskType type;            //mask类型
    int from;           //mask起始位置
    int to;             //mask结束位置
    int padding;        //mask填充长度
    int pos;            //mask位置
};

class Controller //controller肯定是对整个系统的控制，密钥肯定是每次单独生成
//读取图像不在controller中完成，controller只负责生成context，生成密钥，执行加密运算等功能
{
    public:
        string controllerFolder = "NO_FOLDER";
        int circuitDepth;
        int relu_degree = 119;

        Controller() {}

        //生成context/释放context
        void generateContext(int logRing,int logScale,int logPrimes,int digitsHks,int ctsLevels,int stcLevels,int reluDeg,bool serialize=false);
        void generateContext(bool serialize=false);
        void loadContext(bool verbose=true);
        void clear_context();

        //生成密钥/加载密钥/释放密钥
        void generateKeyPair();
        void generateBootstrappingAndRotationKeys(const vector<int>& rotations,
                                                        uint32_t bootstrappingDepth,
                                                        bool serialize,
                                                        const string& filename);
        void generateBootstrappingKeys(int bootstrap_slots);
        void generateRotationKeys(const vector<int>& rotations, bool serialize=false, std::string filename="");
        void load_bootstrapping_and_rotation_keys(const string& filename, int bootstrap_slots);
        void load_rotation_keys(const string& filename);
        void clear_keys();

        //编码/解码
        Ptxt Encode(const vector<double> &vec,int level=0,int slot=0);
        Ptxt Encode(double val, int level, int slot);
        vector<double> Decode(Ctxt &c,int slot);

        //加密/解密
        Ctxt Encrypt(const Ptxt& p);
        Ptxt Decrypt(const Ctxt& c);

        //重写运算符号
        Ctxt Add(const Ctxt& a, const Ctxt& b);
        Ctxt Mul(const Ctxt& a, double b);
        Ctxt Mul(const Ctxt& a, const Ptxt& b);
        
        Ctxt bootstrap(const Ctxt& c,bool timing = false);
        Ctxt bootstrap(const Ctxt& c,int precision, bool timing=false);
        Ctxt relu(const Ctxt& c,double scale,bool timing=false);
        Ctxt relu_wide(const Ctxt& c,double a, double b, int degree, double scale,bool timing=false);

        //神经元函数 卷积+BN
        Ctxt convbn_initial(const Ctxt &c, double scale = 0.5, bool timing=false);
        Ctxt convbn(const Ctxt &c, int layer, int n,ConvConfig config, double scale = 0.5, bool timing=false);
        vector<Ctxt> convbnSx(const Ctxt &c, int layer, int n,ConvConfig config, double scale = 0.5, bool timing=false);
        vector<Ctxt> convbnDx(const Ctxt &c, int layer, int n,ConvConfig config, double scale = 0.5, bool timing=false);
       
        Ctxt downsample1024to256(const Ctxt& c1, const Ctxt& c2);
        Ctxt downsample256to64(const Ctxt &c1, const Ctxt &c2);

        Ctxt rotsum(const Ctxt &in, int slots);
        Ctxt rotsum_padded(const Ctxt &in, int slots);

        Ctxt repeat(const Ctxt &in, int slots);

        Ctxt initLayer(const Ctxt& c, int verbose=0);
        Ctxt layer1(const Ctxt& c, int verbose=0);
        Ctxt layer2(const Ctxt& c, int verbose=0);
        Ctxt layer3(const Ctxt& c, int verbose=0);
        Ctxt classificationLayer(const Ctxt& c,string input_filename,int verbose=0);
        int classificationLayerGetLabel(const Ctxt& c);

        //掩码
        Ptxt generateMask(int n,int level,MaskConfig config,double custom_val);

        //杂项
        void bootstrap_precision(const Ctxt& c);
        void print(const Ctxt& c, int slots = 0, string prefix = "");

    private:
        CryptoContext<DCRTPoly> context;    //每次只生成一个context，这个context将会控制整个系统的加密运算
        KeyPair<DCRTPoly> keyPair;   
        int slotNum;       

        vector<uint32_t> level_budget={4,4};
};


#endif