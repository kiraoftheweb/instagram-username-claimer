import requests, json, random, sys, threading, time, base64, zlib, platform, os, subprocess, uuid, hashlib, bz2, re, warnings, queue as Queue
from base64 import b64decode
from base64 import b64encode
from halo import Halo
from os import system

            class MultiThread:

                def __init__(self, function, args):
                    self.target = function
                    self.threads = []
                    self.args = args

                def create(self, n):
                    for i in range(0, n):
                        t = threading.Thread(target=(self.target), args=(self.args))
                        self.threads.append(t)

                    return self.threads

                def start(self):
                    spinner.start('Starting ' + str(len(self.threads)) + ' threads')
                    for thread in self.threads:
                        time.sleep(1)
                        thread.start()

                    spinner.stop()

                def join(self):
                    for thread in self.threads:
                        time.sleep(2)
                        thread.join()

                    spinner.stop()


            def aes_decode(data, key):
                key = key.encode()
                payload = b64decode(data)
                iv = '\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01'
                cipher = AES.new(key, AES.MODE_CBC, iv)
                text = cipher.decrypt(payload).decode()
                pad = ord(text[(-1)])
                return text[:-pad]


            def aes_encode(text, key):
                key = key.encode()
                text_length = len(text)
                amount_to_pad = AES.block_size - text_length % AES.block_size
                if amount_to_pad == 0:
                    amount_to_pad = AES.block_size
                pad = chr(amount_to_pad)
                payload = (text + pad * amount_to_pad).encode()
                iv = '\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01'
                cipher = AES.new(key, AES.MODE_CBC, iv)
                return b64encode(cipher.encrypt(payload))


            tryn = 0

            def keyExist(key, value):
                try:
                    value = key[value]
                    return True
                except:
                    return False


            def getMachineKey():
                current_machine_id = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
                manufacturer = subprocess.check_output('wmic bios get manufacturer').decode().split('\n')[1].strip()
                mplatform = platform.platform()
                allk = current_machine_id + manufacturer + mplatform
                machine_key = hashlib.md5(allk.encode('utf-8')).hexdigest()
                return machine_key


            def falseLicense():
                if os.path.exists('license.dexy'):
                    os.remove('license.dexy')
                print('\n[-] Failed to validate license\n')
                sys.exit(0)


            def verifylicense(license):
                print('[+] License is valid.\n')


            def license():
                try:
                    with open('license.dexy') as (f):
                        settings = json.load(f)
                    code = settings['license']
                    verifylicense(code)
                except:
                    code = input('Your license code: ')
                    with open('license.dexy', 'a') as (out):
                        out.write('{"license": "' + code + '"}')
                    verifylicense(code)


            def initate(userx, passx):
                global fini
                global r2
                global s
                global ubio
                global uemail
                global ugender
                global uname
                global uphone
                global uurl
                params = {'username':userx, 
                 'password':passx}
                s = requests.session()
                s.verify = False
                url1 = 'https://www.instagram.com/accounts/login/'
                r1 = s.get(url1)
                csrf1 = r1.cookies.get_dict()['csrftoken']
                url2 = 'https://www.instagram.com/accounts/login/ajax/'
                username = params['username']
                password = params['password']
                data2 = {'username':username,  'password':password,  'queryParams':'{}'}
                h2 = {'accept':'*/*',  'accept-encoding':'gzip, deflate, br',  'accept-language':'en-US,en;q=0.9',  'content-type':'application/x-www-form-urlencoded',  'origin':'https://www.instagram.com',  'referer':'https://www.instagram.com/accounts/login/',  'user-agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36',  'x-csrftoken':csrf1,  'x-instagram-ajax':'1',  'x-requested-with':'XMLHttpRequest'}
                r2 = s.post(url2, headers=h2, data=data2)
                if not keyExist(r2.json(), 'authenticated') or r2.json()['authenticated'] == False:
                    print('\n[-] Invalid Account Info Or Sus Request On Instagram')
                    fini = True
                    sys.exit(0)
                else:
                    h2.pop('x-requested-with')
                    h2.pop('x-instagram-ajax')
                    r3 = s.get('https://www.instagram.com/accounts/edit/', headers=h2)
                    gpe = re.findall('{"SettingsPages"\\:\\[(.*)\\]', r3.text)
                    dd = json.loads(gpe[0])
                    uemail = dd['form_data']['email']
                    uphone = dd['form_data']['phone_number']
                    uname = dd['form_data']['first_name']
                    ubio = dd['form_data']['biography']
                    uurl = dd['form_data']['external_url']
                    ugender = dd['form_data']['gender']


            def frt(t):
                return base64.b64decode(t).decode()


            def turbo(userx, passx, targetx):
                global cproxies
                global fini
                global tryn
                try:
                    if fini == True:
                        sys.exit('Done')
                    params = {'username':userx, 
                     'password':passx,  'target':targetx}
                    csrf = r2.cookies.get_dict()['csrftoken']
                    turboin = True
                    hf = {'accept':'*/*',  'accept-encoding':'gzip, deflate, br',  'accept-language':'en-US,en;q=0.9',  'content-type':'application/x-www-form-urlencoded',  'origin':'https://www.instagram.com',  'referer':'https://www.instagram.com/accounts/edit/',  'user-agent':'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36',  'x-csrftoken':csrf,  'x-instagram-ajax':'1',  'x-requested-with':'XMLHttpRequest',  'Connection':'keep-alive'}
                    df = {'first_name':uname,  'email':uemail,  'username':params['target'],  'phone_number':uphone,  'biography':ubio,  'external_url':uurl,  'chaining_enabled':'on'}
                    urlf = 'https://www.instagram.com/accounts/edit/'
                    res = None
                    s.headers.update(hf)
                    showndis = False
                    triedlogin = False
                    while turboin == True:
                        tryn += 1
                        q.put(1)
                        currentproxy = False
                        if fini == True:
                            turboin = False
                            sys.exit('Done')
                        try:
                            if cproxies:
                                rchoice = random.choice(cproxies)
                                currentproxy = {'https': 'https://' + rchoice}
                                if '127.0.0.1:8888' in rchoice:
                                    currentproxy = False
                            else:
                                ggurl = ('https://www.instagram.com/{0}/' + frt('P19fYT0x')).format(params['target'])
                                res = requests.get(ggurl, allow_redirects=False, proxies=currentproxy)
                                if res.text == '{}':
                                    if showndis == False:
                                        showndis = True
                                        print('\n[*] ' + params['target'] + ' is disabled.\n')
                                    if bypass or res.status_code == 404:
                                        bb = s.post(urlf, data=df)
                                        if bb.status_code == 200 or bb.status_code == 301 or bb.status_code == 302:
                                            print('\nCongraz! Claimed: ' + params['target'])
                                            print('\n Threads Killed')
                                            turboin = False
                                            fini = True
                                            sys.exit(0)
                                else:
                                    print(' Failed to grab the username that you want,Sorry!')
                        except:
                            print('\nYour connection is closed to instagram.\n')
                            turboin = False
                            fini = True
                            sys.exit(0)

                except KeyboardInterrupt:
                    sys.exit('Done.')


            if __name__ == '__main__':
                print('Instagram Username Claimer Unpacked By St0rmm')
                userx = input('Please Enter Your Username: ')
                passx = input('\nPlease Enter Your Password: ')
                initate(userx, passx)
                targetx = input('\nWhich username Do You Want To Claim: ')
                try:
                    nthreads = int(input('\nHow many threads do you want to use: '))
                except:
                    nthreads = 1

                bypass = input('\nDo you want to Use swap method [Y/N] ?')
                if bypass.lower() == 'y':
                    bypass = True
                else:
                    bypass = False
                try:
                    proxyfile = input('\n Do you want to use proxies [Https Proxy File]  ')
                    with open(proxyfile) as (f):
                        cproxies = f.readlines()
                    if len(cproxies) > 1:
                        print('\nLoaded Proxies:\n')
                    else:
                        cproxies = False
                        print('\nPlease Load Proxies And Try Again\n')
                except:
                    print('\nPlease Load Proxies And Try Again\n')

                b = MultiThread(turbo, [userx, passx, targetx])
                b.create(nthreads)
                b.start()
                try:
                    bob = 0
                    while 1:
                        time.sleep(1)
                        for i in range(bob, q.qsize()):
                            time.sleep(0.05)
                            spinner.start('How many times do you want to try: ' + str(q.qsize()))

                        bob = q.qsize()
                        if fini == True:
                            break

                except KeyboardInterrupt:
                    fini = True
                    spinner.stop()

        except:
            input('\nPress anything to exit the program...\n')

    else:
        print(checkauth.text)
        sys.exit()
