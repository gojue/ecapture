# python3 https_client.py
import urllib.request
import urllib.error

try:
    response = urllib.request.urlopen('https://www.baidu.com')
    print('response headers: "%s"' % response.info())
    print('response headers: "%s"' % response.read().decode())

except urllib.error.HTTPError as e:
    print('http error code: ', e.code)
except urllib.error.URLError as e:
    print("can't connect, reason: ", e.reason)