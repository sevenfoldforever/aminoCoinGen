import os
from tkinter import Label, Button, messagebox, Entry, BooleanVar, scrolledtext
from tkinter import Tk
from tkinter.ttk import Checkbutton, Combobox
from tkinter import filedialog
import tkinter.messagebox as mb
from datetime import datetime
from tkinter import ttk


import asyncio
import aiohttp
import random
import time
import os
from threading import Thread
import telebot
import requests
from gtts import gTTS
from playsound import playsound



import json
from hmac import new
from typing import Union
from hashlib import sha1
from base64 import b64encode
import hmac
from os import urandom
from time import time as timestamp
from json_minify import json_minify
from time import timezone
from uuid import UUID
from binascii import hexlify

"""
Made By Xsarz -> @DXsarz

GitHub: https://github.com/xXxCLOTIxXx
Telegram channel: https://t.me/DxsarzUnion
YouTube: https://www.youtube.com/channel/UCNKEgQmAvt6dD7jeMLpte9Q
Discord server: https://discord.gg/GtpUnsHHT4
"""


class UnknownError(Exception):
    def __init__(*args, **kwargs):
        Exception.__init__(*args, **kwargs)


class AccountDisabled(Exception):
    def __init__(*args, **kwargs):
        Exception.__init__(*args, **kwargs)



class AccountLimitReached(Exception):
    def __init__(*args, **kwargs):
        Exception.__init__(*args, **kwargs)


class TooManyRequests(Exception):
    def __init__(*args, **kwargs):
        Exception.__init__(*args, **kwargs)

class ActionNotAllowed(Exception):
    def __init__(*args, **kwargs):
        Exception.__init__(*args, **kwargs)

class IpTemporaryBan(Exception):
    def __init__(*args, **kwargs):
        Exception.__init__(*args, **kwargs)

class InvalidRequest(Exception):
    def __init__(*args, **kwargs):
        Exception.__init__(*args, **kwargs)



class Generator():
    def __init__(self):
    	PREFIX = bytes.fromhex("42")
    	SIG_KEY = bytes.fromhex("F8E7A61AC3F725941E3AC7CAE2D688BE97F30B93")
    	DEVICE_KEY = bytes.fromhex("02B258C63559D8804321C5D5065AF320358D366F")


    def deviceId(self):
        try:
            with open("device.json", "r") as stream:
                data = json.load(stream)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            device = self.generate_device_info()
            with open("device.json", "w") as stream:
                json.dump(device, stream, indent=4)
            with open("device.json", "r") as stream:
                data = json.load(stream)
        return data


    def generate_device_info(self):
        identifier = urandom(20)
        key = bytes.fromhex("02B258C63559D8804321C5D5065AF320358D366F")
        mac = hmac.new(key, bytes.fromhex("42") + identifier, sha1)
        device = f"42{identifier.hex()}{mac.hexdigest()}".upper()
        return {
            "device_id": device,
            "user_agent": "Dalvik/2.1.0 (Linux; U; Android 5.1.1; SM-G973N Build/beyond1qlteue-user 5; com.narvii.amino.master/3.5.33562)"
        }

    def signature(self, data) -> str:
        try: dt = data.encode("utf-8")
        except Exception: dt = data
        mac = new(bytes.fromhex("F8E7A61AC3F725941E3AC7CAE2D688BE97F30B93"), dt, sha1)
        return b64encode(bytes.fromhex("42") + mac.digest()).decode("utf-8")



class headers():
	def __init__(self, data = None, content_type = None, deviceId: str = None, sid: str = None):
		self.device = Generator().deviceId()
		self.User_Agent = self.device["user_agent"]
		self.sid = sid
		if deviceId!=None:self.device_id = deviceId
		else:self.device_id = self.device["device_id"]


		self.headers = {
			"NDCDEVICEID": self.device_id,
			"Accept-Language": "en-US",
			"Content-Type": "application/json; charset=utf-8",
			"User-Agent": self.User_Agent,
			"Host": "service.narvii.com",
			"Accept-Encoding": "gzip",
			"Connection": "Upgrade"
		}

		if data is not None:
			self.headers["Content-Length"] = str(len(data))
			self.headers["NDC-MSG-SIG"] = Generator().signature(data=data)
		if self.sid is not None:
			self.headers["NDCAUTH"] = f"sid={self.sid}"
		if content_type is not None:
			self.headers["Content-Type"] = content_type




class AminoClient:
    def __init__(self, proxies: dict = None, deviceId: str = None):
        self.api = "https://service.narvii.com/api/v1"
        self.email = 'Guest'
        self.headersType = 'app'
        self.proxies = proxies
        self.uid = None
        self.sid = None
        self.session = requests.Session()
        if deviceId:self.deviceId=deviceId
        else:self.deviceId=Generator().deviceId()['device_id']
        self.session_async=aiohttp.ClientSession()


    def __del__(self):
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(self._close_session())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(self._close_session())

    async def _close_session(self):
        if not self.session_async.closed: await self.session_async.close()


    def parser(self, data = None, content_type: str = None):
        return headers(data=data, content_type=content_type, deviceId=self.deviceId, sid=self.sid).headers

    def login(self, email: str, password: str):
        data = json.dumps({
            "email": email,
            "v": 2,
            "secret": f"0 {password}",
            "deviceID": self.deviceId,
            "clientType": 100,
            "action": "normal",
            "timestamp": int(timestamp() * 1000)
        })
        with self.session.post(f"{self.api}/g/s/auth/login",  headers=self.parser(data=data), data=data, proxies=self.proxies) as response:
            if response.status_code != 200:self.checkExceptions(response.text)
            else:json_response = json.loads(response.text)
        self.sid = json_response["sid"]
        self.uid = json_response["account"]["uid"]
        return self.uid


    def logout(self):

        data = json.dumps({
            "deviceID": self.deviceId,
            "clientType": 100,
            "timestamp": int(timestamp() * 1000)
        })
        response = self.session.post(f"{self.api}/g/s/auth/logout", headers=self.parser(data=data), data=data, proxies=self.proxies)
        if response.status_code != 200:self.checkExceptions(response.text)
        else:
            self.sid = None
            self.uid = None
            self.email = 'Guest'
        return response.status_code


    def get_from_link(self, link: str):
        response = self.session.get(f"{self.api}/g/s/link-resolution?q={link}", headers=self.parser(), proxies=self.proxies)
        if response.status_code != 200:self.checkExceptions(response.text)
        else: return json.loads(response.text)["linkInfoV2"]



    def get_wallet_info(self):
        response = self.session.get(f"{self.api}/g/s/wallet", headers=self.parser(), proxies=self.proxies)
        if response.status_code != 200:self.checkExceptions(response.text)
        else:return json.loads(response.text)["wallet"]

    def join_community(self, comId: str, invitationId: str = None):

        data = {"timestamp": int(timestamp() * 1000)}
        if invitationId: data["invitationId"] = invitationId

        data = json.dumps(data)
        response = self.session.post(f"{self.api}/x{comId}/s/community/join", data=data, headers=self.parser(data=data), proxies=self.proxies)
        if response.status_code != 200:self.checkExceptions(response.text)
        else: response.status_code

    async def send_active_obj(self, comId: str, tz: int = -timezone // 1000, timers: list = None):
        data = {"userActiveTimeChunkList": timers, "timestamp": int(timestamp() * 1000), "optInAdsFlags": 2147483647, "timezone": tz}
        data = json_minify(json.dumps(data))

        async with self.session_async.post(f"{self.api}/x{comId}/s/community/stats/user-active-time", proxy=self.proxies,headers=self.parser(data=data), data=data) as response:
            if response.status != 200:self.checkExceptions(await response.text())
            else:return response.status







    async def send_coins(self, comId, coins: int, blogId: str = None, chatId: str = None, objectId: str = None, transactionId: str = None):
        if transactionId is None: transactionId = str(UUID(hexlify(urandom(16)).decode('ascii')))

        data = {
            "coins": coins,
            "tippingContext": {"transactionId": transactionId},
            "timestamp": int(timestamp() * 1000)
        }

        if blogId is not None:url = f"{self.api}/x{comId}/s/blog/{blogId}/tipping"
        elif chatId is not None:url = f"{self.api}/x{comId}/s/chat/thread/{chatId}/tipping"
        elif objectId is not None:
            data["objectId"] = objectId
            data["objectType"] = 2
            url = f"{self.api}/x{comId}/s/tipping"

        data = json.dumps(data)
        async with self.session_async.post(url, proxy=self.proxies,headers=self.parser(data=data), data=data) as response:
            if response.status != 200:self.checkExceptions(await response.text())
            else:return response.status

        self.__del__()

    def checkExceptions(self, data):


        try:
            data = json.loads(data)
            try:api_code = data["api:statuscode"]
            except:raise UnknownError(data)
        except json.decoder.JSONDecodeError:api_code = 403

        if api_code == 110:raise ActionNotAllowed(data)
        elif api_code == 201 or api_code == 210:raise AccountDisabled(data)
        elif api_code == 403:raise IpTemporaryBan(data)
        elif api_code == 219:raise AccountLimitReached(data) or TooManyRequests(data)
        elif api_code == 104:raise InvalidRequest(data)
        else:raise Exception(data)


class App():
    def __init__(self):
        self.file = ''
        self.window = Tk()
        self.window.title("CoinGen")
        self.window.geometry('210x210')
        self.window.resizable(width=False, height=False)
        self.process=False
        self.stop=False
        self.telegram=False
        self.logined=False
        self.sound = True
        self.email=None
        self.proxies=None
        self.uid=None
        self.token=None
        self.Tgclient=None
        self.main()


    def TZ(self):
        localhour = time.strftime("%H", time.gmtime())
        localminute = time.strftime("%M", time.gmtime())
        UTC = {"GMT0": '+0', "GMT1": '+60', "GMT2": '+120', "GMT3": '+180', "GMT4": '+240', "GMT5": '+300', "GMT6": '+360',
                "GMT7": '+420', "GMT8": '+480', "GMT9": '+540', "GMT10": '+600', "GMT11": '+660', "GMT12": '+720',
                "GMT13": '+780', "GMT-1": '-60', "GMT-2": '-120', "GMT-3": '-180', "GMT-4": '-240', "GMT-5": '-300',
                "GMT-6": '-360', "GMT-7": '-420', "GMT-8": '-480', "GMT-9": '-540', "GMT-10": '-600', "GMT-11": '-660'};
        hour = [localhour, localminute]
        if hour[0] == "00": tz = UTC["GMT-1"];return int(tz)
        if hour[0] == "01": tz = UTC["GMT-2"];return int(tz)
        if hour[0] == "02": tz = UTC["GMT-3"];return int(tz)
        if hour[0] == "03": tz = UTC["GMT-4"];return int(tz)
        if hour[0] == "04": tz = UTC["GMT-5"];return int(tz)
        if hour[0] == "05": tz = UTC["GMT-6"];return int(tz)
        if hour[0] == "06": tz = UTC["GMT-7"];return int(tz)
        if hour[0] == "07": tz = UTC["GMT-8"];return int(tz)
        if hour[0] == "08": tz = UTC["GMT-9"];return int(tz)
        if hour[0] == "09": tz = UTC["GMT-10"];return int(tz)
        if hour[0] == "10": tz = UTC["GMT13"];return int(tz)
        if hour[0] == "11": tz = UTC["GMT12"];return int(tz)
        if hour[0] == "12": tz = UTC["GMT11"];return int(tz)
        if hour[0] == "13": tz = UTC["GMT10"];return int(tz)
        if hour[0] == "14": tz = UTC["GMT9"];return int(tz)
        if hour[0] == "15": tz = UTC["GMT8"];return int(tz)
        if hour[0] == "16": tz = UTC["GMT7"];return int(tz)
        if hour[0] == "17": tz = UTC["GMT6"];return int(tz)
        if hour[0] == "18": tz = UTC["GMT5"];return int(tz)
        if hour[0] == "19": tz = UTC["GMT4"];return int(tz)
        if hour[0] == "20": tz = UTC["GMT3"];return int(tz)
        if hour[0] == "21": tz = UTC["GMT2"];return int(tz)
        if hour[0] == "22": tz = UTC["GMT1"];return int(tz)
        if hour[0] == "23": tz = UTC["GMT0"];return int(tz)



    def timers(self):return [{'start': int(time.time()), 'end': int(time.time()) + 300} for _ in range(50)]

    def date_now(self): return str(datetime.now()).split(" ")[0].replace("-", ".")

    def time_now(self): return str(datetime.now()).split(" ")[1].split(".")[0]

    def create_time(self): return f'{self.date_now()} - {self.time_now()}'


    def login(self):
        try:
            if self.logined == False:
                if self.gmail_e.get() == '' or self.password_e.get() == '':mb.showerror("Logout error", f'Enter email and password.')
                else:
                    self.mainClient.login(email=self.gmail_e.get(), password=self.password_e.get())
                    self.logined=True
                    self.checkBalanse()
                    self.log(f'Login as {self.gmail_e.get()}.')
                    with open("session.txt", 'w+') as file:
                        file.write(f"{self.gmail_e.get()} {self.password_e.get()}")
                        file.close()
            else:mb.showwarning("Login", 'You are already logged in.')
        except Exception as error:mb.showerror("Login error", f'Failed login:\n{error}')

    def checkBalanse(self):
        try:
            self.bal = self.mainClient.get_wallet_info()['totalCoins']
            self.balance['text']=f'Balance: {str(self.bal)} AM'
        except:pass


    def logout(self):
        try:
            if self.logined == True:
                self.mainClient.logout()
                self.logined=False
                self.balance['text']="Balance: Account not connected."
                self.log(f'Logout.')
            else:mb.showwarning("Logout", 'You are not logged in.')
        except Exception as error:mb.showerror("Logout error", f'Failed logout:\n{error}')

    def AutoLogin(self):
        try:
            if self.logined == False:
                if 'session.txt' not in os.listdir():mb.showerror("Session error", f'File with previous session not found.')
                else:
                    with open('session.txt', 'r') as file:
                        account = file.read().split(" ")
                        email=account[0]
                        self.mainClient.login(email=email, password=account[1])
                        self.logined=True
                        self.log(f'Login as {email}.')
                    self.checkBalanse()
            else:mb.showwarning("Login", 'You are already logged in.')
        except Exception as error:mb.showerror("Login error", f'Failed login:\n{error}')

    def connect(self, url: str = 'http://google.com', proxy = None):
        try:requests.get(url, proxies=proxy);return True
        except: mb.showerror("Link info error", 'No internet connection.');return False

    def log(self, text):
        if 'LOG.txt' not in os.listdir():open('LOG.txt', 'w')
        with open('LOG.txt', 'r') as file:
            log = file.read()
            file.close()
        with open('LOG.txt', 'w') as file:
            file.write(f"{log}\n[{self.create_time()}] {text}")
            file.close()
        self.log_text.configure(state='normal')
        self.log_text.insert(0.1, f"\n[{self.create_time()}] {text}")
        self.log_text.configure(state='disabled')

    def notif(self, text):
        if self.chk_state.get():
            if self.telegram_notif.get():
                if self.telegram:
                    try:self.Tgclient.send_message(self.uid, f"[{self.create_time()}] {text}")
                    except:self.log("Unable to send message to telegram.")
            if self.sound_notif.get() :
                s = gTTS(text, lang=self.langs.get(), slow=False)
                s.save('out.mp3')
                playsound('out.mp3')

    def get_file(self):
        self.file = filedialog.askopenfilename()
        if self.file == '':self.file_btn['text']="Select account file"
        else:self.file_btn["text"]="File selected"



    def pause(self):
        if self.stop == False:self.stop=True;self.log("Pause.")
        elif self.stop == True:self.stop=False;self.log("Work resumed.")


    def getLink(self):
        try:
            self.linkInfo = self.mainClient.get_from_link(self.link.get())
            self.comId = self.linkInfo['extensions']['linkInfo']['ndcId']
            self.blogId = self.linkInfo['extensions']['linkInfo']['objectId']
            return True
        except Exception as error:mb.showerror("Error", f'Failed to retrieve information from link:\n{error}');return False


    def stop_func(self):
        self.process=True
        self.log("Closing the program...")
        exit()

    def tg_add(self):
        token = self.bot.get()
        uid = self.user.get()

        if token !='' and uid !='':
            self.Tgclient = telebot.TeleBot(token)
            self.telegram=True
            self.uid=uid
            self.token=token
            self.notif('OK.')
            mb.showinfo("CoinGen", 'OK.')
        else:mb.showerror("Error", f'Enter all data')

    def tg_remove(self):
        self.telegram=False
        self.uid=None
        self.token=None
        self.Tgclient=None
        mb.showinfo("CoinGen", 'OK.')

    def startProcess(self):
        self.mainClient = AminoClient()
        if self.connect() and self.getLink():
            if self.link.get() == '':mb.showerror("Error", 'Provide a link to the post.')
            elif self.file == '':mb.showerror("Error", 'Select a file with accounts (.txt format).')
            else:
                mb.showinfo("Important", "The community in which the post is created must be open and you must be level 5+ (in order to send coins).")

                self.start_btn.destroy()
                self.file_btn.destroy()
                self.link_lbl.destroy()
                self.link.destroy()
                self.notifications.destroy()
                self.window.geometry('1000x790')

                self.tabs = ttk.Notebook(self.window)
                self.tab1 = ttk.Frame(self.tabs)
                self.tab2 = ttk.Frame(self.tabs)
                self.tab3 = ttk.Frame(self.tabs)
                self.tab4 = ttk.Frame(self.tabs)
                self.TGSettings = ttk.Frame(self.tabs)
                self.tabs.add(self.tab1, text='Process')
                self.tabs.add(self.tab2, text='Login')
                self.tabs.add(self.tab3, text='Settings')
                self.tabs.add(self.tab4, text='Proxy')
                self.tabs.add(self.TGSettings, text='Telegram')






                self.sound_notif = BooleanVar()
                self.telegram_notif  = BooleanVar()
                self.sound_notif.set(True)
                self.telegram_notif.set(True)
                self.chk_state.set(True)
                self.langs = Combobox(self.tab3, state="readonly")
                self.langs['values'] = ('en', 'ru')
                self.langs.current(0)
                self.langs.grid(column=1, row=1)
                Label(self.tab3, text="").grid(column=0, row=0, pady=100, padx=280)
                Label(self.tab3, text="Notification language:").grid(column=0, row=1, pady=15)
                Checkbutton(self.tab3, text='Telegram Notification', var=self.telegram_notif).grid(column=0, row=2)
                Checkbutton(self.tab3, text='Sound Notification', var=self.sound_notif).grid(column=1, row=2, pady=15)


                self.bot_lbl = Label(self.TGSettings, text="Telegram bot token")
                self.bot = Entry(self.TGSettings)
                self.user_lbl = Label(self.TGSettings, text="Your Telegram ID")
                self.user = Entry(self.TGSettings)
                self.decotr_2 = Label(self.TGSettings, text="", padx=480, pady=100)

                self.Apply_tg = Button(self.TGSettings, text="Apply", command=self.tg_add)
                self.remove_tg = Button(self.TGSettings, text="Clear Data", command=self.tg_remove)

                self.decotr_2.grid(column=0, row=0)
                self.bot_lbl.grid(column=0, row=1)
                self.bot.grid(column=0, row=2)
                self.user_lbl.grid(column=0, row=3)
                self.user.grid(column=0, row=4)
                self.Apply_tg.grid(column=0, row=5)
                self.remove_tg.grid(column=0, row=6, pady=10)
                Label(self.TGSettings, text="@DXsarz -> Telegram").grid(column=0, row=7)


                self.balance = Label(self.window, text="Balance: Account not connected.")
                self.log_text = scrolledtext.ScrolledText(self.tab1, width=120, height=28)
                self.stop_btn = Button(self.tab1, text="STOP", command=self.stop_func)
                self.pause_btn = Button(self.tab1, text="PAUSE", command=self.pause)
                self.restart_btn = Button(self.tab1, text="RESTART", command=lambda: Thread(target=self.restart).start())


                self.email_lbl = Label(self.tab2, text="Email")
                self.password_e = Entry(self.tab2)
                self.gmail_e = Entry(self.tab2)
                self.password_lbl = Label(self.tab2, text="Password")
                self.login = Button(self.tab2, text="Login", command=self.login)
                self.auto_login = Button(self.tab2, text="Automatic login", command=self.AutoLogin)
                self.logout = Button(self.tab2, text="Logout", command=self.logout)
                self.notifications = Checkbutton(self.tab1, text='Notifications', var=self.chk_state)

                self.decotr_1 = Label(self.tab4, text="")
                self.Apply_proxy = Button(self.tab4, text="Apply", command=lambda: Thread(target=self.setProxy).start())
                self.clear_prox = Button(self.tab4, text="Clear proxy", command=self.clearProxy)
                self.https_prox = Label(self.tab4, text="HTTPS: None")
                self.https_e = Entry(self.tab4)

                self.decotr_1.grid(column=0, row=0, padx=480, pady=100)
                self.https_prox.grid(column=0, row=1)
                self.https_e.grid(column=0, row=2)
                self.Apply_proxy.grid(column=0, row=5, pady=10)
                self.clear_prox.grid(column=0, row=6,)
                Label(self.tab4, text="@DXsarz -> Telegram").grid(column=0, row=7)


                self.log_text.grid(column=0, row=0, padx=10)
                self.pause_btn.grid(column=0, row=5, padx=10, pady=15)
                self.stop_btn.grid(column=0, row=6, padx=10)
                self.restart_btn.grid(column=0, row=7, padx=10, pady=15)
                self.notifications.grid(column=0, row=4, pady=15)

                self.email_lbl.grid(column=0, row=0, pady=15, padx=480)
                self.gmail_e.grid(column=0, row=1, pady=15)
                self.password_lbl.grid(column=0, row=2, pady=15)
                self.password_e.grid(column=0, row=3, pady=15)
                self.login.grid(column=0, row=4, pady=15)
                self.auto_login.grid(column=0, row=5, pady=15)
                self.logout.grid(column=0, row=6, pady=15)
                Label(self.tab2, text="@DXsarz -> Telegram").grid(column=0, row=7)
                self.balance.grid(column=0, row=19)
                Label(self.window, text="-= Made by Xsarz =-").grid(column=0, row=20)




                self.tabs.grid(column=0, row=0)
                self.log('Starting...')
                Thread(target=self.start).start()



    def start(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.mainProcess())


    def setProxy(self):
        https = self.https_e.get()
        if https != '':
            self.proxies = {"https": https}
            self.https_prox['text']=f"HTTPS: {https}"


    def clearProxy(self):
        self.https_prox['text']=f"HTTPS: None"
        self.proxies=None

    def main(self):
        self.start_btn = Button(self.window, text="Start", command=lambda: self.startProcess())
        self.file_btn = Button(self.window, text="Select account file", command=lambda: self.get_file())
        self.link_lbl = Label(self.window, text="Link to post to send coins")
        self.link = Entry()
        self.chk_state = BooleanVar()
        self.chk_state.set(True)
        self.notifications = Checkbutton(self.window, text='Notifications', var=self.chk_state)

        self.notifications.grid(column=0, row=4, pady=15, padx=20)
        self.link_lbl.grid(column=0, row=5, pady=5, padx=20)
        self.link.grid(column=0, row=6)
        self.file_btn.grid(column=0, row=7, pady=20)

        self.start_btn.grid(column=0, row=19)

        self.window.mainloop()



    def restart(self):
        self.process=True
        self.log('----\\\RESTART///----')
        time.sleep(5)
        self.process=False
        self.start()


    def st(self):
        while True:
            if self.process:exit()
            if self.stop:time.sleep(1)
            else:break

    async def send(self, client):
        coins = client.get_wallet_info()['totalCoins']
        try:
            if coins > 500:
                for _ in range(coins // 500):await client.send_coins(comId=self.comId, coins=500, blogId=self.blogId)
            if coins:await client.send_coins(comId=self.comId, coins=coins % 500, blogId=self.blogId)
        except:pass
        self.log(f"Sent {str(coins)} coins.")

    async def mainProcess(self):
        try:accounts = open(self.file).read().split('\n');random.shuffle(accounts)
        except FileNotFoundError:log('The selected account with files was not found. It may have been removed.');mb.showerror("Error", f'The selected account with files was not found. It may have been removed.');return
        while True:
            if self.process:exit()
            if self.stop!=True:
                try:
                    bot_acc = accounts[0]
                    accounts.remove(bot_acc);accounts.append(bot_acc)
                    email, password, deviceId = bot_acc.split(" ")
                    self.email=email
                    client = AminoClient(deviceId=deviceId, proxies=self.proxies)
                    client.login(email, password)
                    self.log(f"{email} Authorized.")
                    try:client.join_community(self.comId)
                    except:pass
                    try:
                        for _ in range(1, 25):
                            if self.process:exit()
                            if self.stop:self.st()
                            await client.send_active_obj(comId=self.comId, timers=self.timers(), tz=self.TZ())
                            self.log(f"Sent {str(_)} ACTIVE-OBJ out of 24.")
                            time.sleep(2.5)
                    except AccountLimitReached or TooManyRequests:pass
                    except InvalidRequest:self.log(f"Invalid request. -> {self.email}.");self.notif(self.lang_txt('Invalid'))
                    await self.send(client=client)
                    if self.logined:self.checkBalanse()


                except AccountLimitReached or TooManyRequests:self.log(f"Too many requests -> {self.email}.");continue
                except AccountDisabled:self.log(f"Account disabled (banned) -> {self.email}.");self.notif(self.lang_txt('acc_dis', self.email));continue
                except ActionNotAllowed:self.log(f"Action not allowed -> {self.email}.");continue
                except IpTemporaryBan:self.log(f"Banned by ip (403), the process will be restored in 360 seconds -> {self.email}.");self.notif(self.lang_txt('403'));time.sleep(360);continue
                except Exception as error:self.log(f"Error -> {self.email}:\n{error}\n");self.notif(self.lang_txt('err'));continue

    def lang_txt(self, code, email = None):
        text = {
            'ru':{
                'err':'Непредвиденная ошибка, смотрите в логе.',
                '403':'403 - временный бан ip, процесс продолжится через 360 сек.',
                'acc_dis':f'Аккаунт {email} отключен.',
                'Invalid':'Неверный запрос.'
            },
            'en':{
                'err':'Unexpected error, see log.',
                '403':'403 - temporary ip ban, the process will continue in 360 seconds.',
                'acc_dis':f'Account {email} disabled.',
                'Invalid':'Invalid request.'
            }
        }
        return text[self.langs.get()][code]


if __name__ == '__main__':
    App()
