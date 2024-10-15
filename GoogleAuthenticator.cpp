#include "GoogleAuthenticator.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cmath>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>

// 时间步长（单位：秒）
const int kTimePeriod = 30;
// Base32 字符集
const char* kBase32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// 设置密钥，如果需要编码，则进行 Base32 编码
void GoogleAuthenticator::SetSecret(const std::string& s, bool bNeedEndcode) {
    m_secret = bNeedEndcode ? Base32Encode(s) : s;
}

// 生成随机密钥，长度为 32
std::string GoogleAuthenticator::GenerateSecret() {
    std::string secret;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 31);

    for (int i = 0; i < 32; ++i) {
        secret += kBase32Chars[dis(gen)];
    }
    return secret;
}

// 生成验证码
std::string GoogleAuthenticator::GenerateCodeForTimeSlice(long timeSlice) {
    // 30 秒为一个时间步
    long timestamp = timeSlice / kTimePeriod;
    auto paddedSecret = AddBase32Padding(m_secret);

    std::string key;
    Base32Decode(paddedSecret, key);

    // 确保计数器以大端序处理
    unsigned char buf[8];
    EncodeCounterBigEndian(timestamp, buf);

    // 使用 HMAC-SHA1 生成哈希值
    auto hmacResult = HmacSha1(key, std::string((char*)buf, 8));

    // 动态截断算法 (Dynamic Truncation)
    int offset = hmacResult[hmacResult.size() - 1] & 0x0F;
    int binary = ((hmacResult[offset] & 0x7F) << 24) |
                 ((hmacResult[offset + 1] & 0xFF) << 16) |
                 ((hmacResult[offset + 2] & 0xFF) << 8) |
                 (hmacResult[offset + 3] & 0xFF);

    // 生成 6 位 OTP
    int code = binary % 1000000;

    // 返回填充为 6 位的字符串
    std::ostringstream oss;
    oss << std::setw(6) << std::setfill('0') << code;
    return oss.str();
}

// 校验验证码是否正确
bool GoogleAuthenticator::ValidateCode(const std::string &inputCode,
    int discrepancy, long curTimeSlice) {
    if (inputCode.length() != 6) {
        return false;
    }

    if (curTimeSlice == 0) {
        curTimeSlice = time(nullptr);
    }

    // 遍历时间漂移范围内的时间片 (-discrepancy 到 +discrepancy)
    for (int i = -discrepancy; i <= discrepancy; ++i) {
        // 使用带有时间片偏移量的时间戳生成验证码
        long timeSlice = curTimeSlice + i * kTimePeriod;
        auto generatedCode = GenerateCodeForTimeSlice(timeSlice);

        // 如果生成的验证码与输入验证码匹配，返回 true
        if (generatedCode == inputCode) {
            return true;
        }
    }

    // 如果在漂移范围内没有找到匹配的验证码，返回 false
    return false;
}

// 生成用于生成二维码的 URL
std::string GoogleAuthenticator::GetQRCodeURL(const std::string& account,
    const std::string &title, int width, int height, const std::string &level) const
{
    auto otpauth = "otpauth://totp/" + UrlEncode(account) + "?secret=" + m_secret;
    if (!title.empty()) {
        otpauth += "&issuer=" + UrlEncode(title);
    }

    auto urlEncoded = UrlEncode(otpauth);
    return "https://api.qrserver.com/v1/create-qr-code/?data=" + urlEncoded +
           "&size=" + std::to_string(width) + "x" + std::to_string(height) +
           "&ecc=" + level;
}

// HMAC-SHA1 算法实现
std::string GoogleAuthenticator::HmacSha1(const std::string &key, const std::string &data) const {
    unsigned int len;
    unsigned char result[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha1(), key.c_str(), key.size(),
        (unsigned char *)data.c_str(), data.size(), result, &len);

    std::ostringstream hex;
    for (unsigned int i = 0; i < len; ++i) {
        hex << std::setw(2) << std::setfill('0') << std::hex << (int)result[i];
    }
    return std::string(reinterpret_cast<char*>(result), len);
}

// URL 编码实现
std::string GoogleAuthenticator::UrlEncode(const std::string& str) const {
    std::string temp;
    auto len = str.length();

    for (size_t i = 0; i < len; i++) {
        if (isalnum(static_cast<unsigned char>(str[i]))
            || (str[i] == '-') || (str[i] == '_') || (str[i] == '.') || (str[i] == '~')) {
            temp += str[i];
        } else if (str[i] == ' ') {
            temp += "+";
        } else {
            temp += '%';
            temp += ToHex(static_cast<unsigned char>(str[i] >> 4));
            temp += ToHex(static_cast<unsigned char>(str[i] % 16));
        }
    }
    return temp;
}

// 将计数器值按大端序编码为字节数组
void GoogleAuthenticator::EncodeCounterBigEndian(uint64_t counter, unsigned char* buf) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = counter & 0xFF;
        counter >>= 8;
    }
}

// Base32 编码实现
std::string GoogleAuthenticator::Base32Encode(const std::string &input) const {
    int buffer = 0;
    int bitsLeft = 0;
    std::string output;

    for (unsigned char c : input) {
        buffer = (buffer << 8) + c;
        bitsLeft += 8;

        while (bitsLeft >= 5) {
            output.push_back(kBase32Chars[(buffer >> (bitsLeft - 5)) & 0x1F]);
            bitsLeft -= 5;
        }
    }

    if (bitsLeft > 0) {
        output.push_back(kBase32Chars[(buffer << (5 - bitsLeft)) & 0x1F]);
    }

    return output;
}

// Base32 解码实现
bool GoogleAuthenticator::Base32Decode(const std::string &input, std::string& output) const {
    int buffer = 0;
    int bitsLeft = 0;
    auto inputLen = input.length();

    for (size_t i = 0; i < inputLen; ++i) {
        char c = input[i];
        if (c == '=') {
            break;
        }

        auto pos = strchr(kBase32Chars, c);
        if (pos == nullptr) {
            return false;
        }

        int val = pos - kBase32Chars;
        buffer = (buffer << 5) + val;
        bitsLeft += 5;

        if (bitsLeft >= 8) {
            output.push_back((buffer >> (bitsLeft - 8)) & 0xFF);
            bitsLeft -= 8;
        }
    }

    return true;
}

// 添加 Base32 填充字符 '='
std::string GoogleAuthenticator::AddBase32Padding(const std::string& secret) const {
    auto paddedSecret = secret;
    auto remainder = paddedSecret.size() % 8;
    if (remainder != 0) {
        // 添加 '=' 填充，使密钥长度为 8 的倍数
        paddedSecret += std::string(8 - remainder, '=');
    }
    return paddedSecret;
}

// 将数值转换为十六进制字符
unsigned char GoogleAuthenticator::ToHex(unsigned char x) const {
    return x > 9 ? x + 55 : x + 48;
}