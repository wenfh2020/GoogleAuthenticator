#pragma once

#include <string>

class GoogleAuthenticator {
public:
    GoogleAuthenticator() {}
    // 生成随机密钥
    std::string GenerateSecret();
    // 设置密钥
    void SetSecret(const std::string& s, bool bNeedEndcode=true);
    // 获取密钥
    std::string GetSecret() const { return m_secret; }
    // 生成验证码
    std::string GenerateCodeForTimeSlice(long timeSlice);
    // 验证验证码（discrepancy 允许误差步长个数）
    bool ValidateCode(const std::string &inputCode, int discrepancy=1, long curTimeSlice=0);
    // 生成二维码 URL
    std::string GetQRCodeURL(const std::string& account, const std::string &title,
        int width = 200, int height = 200, const std::string &level = "M") const;

private:
    // HMAC-SHA1 实现
    std::string HmacSha1(const std::string &key, const std::string &data) const;
    // Base32 编码实现
    std::string Base32Encode(const std::string &input) const;
    // Base32 解码实现
    bool Base32Decode(const std::string &input, std::string& output) const;
    // 添加 Base32 填充字符 '='
    std::string AddBase32Padding(const std::string& secret) const;
    // 将计数器值按大端序编码为字节数组
    void EncodeCounterBigEndian(uint64_t counter, unsigned char* buf);
    // URL 编码实现
    std::string UrlEncode(const std::string& str) const;
    // 将数值转换为十六进制字符
    unsigned char ToHex(unsigned char x) const;

private:
    std::string m_secret;
};
