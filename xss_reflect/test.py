import requests

# 1. 最简单的请求
response = requests.get('http://httpbin.org/headers')
print(response.json()['headers'])