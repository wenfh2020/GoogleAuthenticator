# GoogleAuthenticator
cpp/c++ GoogleAuthenticator

---

## interface 

```cpp
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
};
```

---

## test

```cpp
// g++ -std=c++17 -o t main.cpp GoogleAuthenticator.cpp -lssl -lcrypto && ./t
int main() {
    GoogleAuthenticator ga;

    // 生成随机密钥
    auto secret = ga.GenerateSecret();
    // 设置固定密钥
    // auto secret = "5TE7J7TN4LJGMWPXCXD5CFAKDJJPQT3L";
    ga.SetSecret(secret);
    std::cout << "Old Secret: " << secret << std::endl
              << "New Secret: " << ga.GetSecret() << std::endl;

    // 生成二维码 URL
    auto title = "example";
    auto account = "test";
    auto qrCodeURL = ga.GetQRCodeURL(account, title);

    std::cout << "Title: " << title << std::endl;
    std::cout << "Account: " << account << std::endl;
    std::cout << "QR code url: " << qrCodeURL << std::endl;

    // 生成验证码
    auto code = ga.GenerateCodeForTimeSlice(time(nullptr));
    std::cout << GetNowTime() << ", Current code: " << code << std::endl;

    // 校验验证码
    bool isValid = ga.ValidateCode(code);
    std::cout << (isValid ? "Check code ok!" : "Check code fail!") << std::endl;
    
    int i = 0;
    while (++i <= 30) {
        code = ga.GenerateCodeForTimeSlice(time(nullptr));
        std::cout << GetNowTime() << ", Current code: " << code << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // 校验验证码（测试时间误差）
    std::cout << "Input code to check:" << std::endl;
    std::cin >> code;
    isValid = ga.ValidateCode(code);
    std::cout << GetNowTime() << ", "
              << (isValid ? "Check code ok!" : "Check code fail!")
              << std::endl;
    return 0;
}
```

