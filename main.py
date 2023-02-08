from asyncio import get_event_loop, new_event_loop, new_event_loop, set_event_loop
from aiohttp import ClientSession
from random import shuffle
from time import strftime, gmtime, timezone, sleep
from time import time as timestamp
from os import urandom, system
from requests import Session
import json
from hmac import new
from hashlib import sha1
from base64 import b64encode
from json_minify import json_minify
from colored import fore
from typing import Union
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

class PasswordError(Exception):
	def __init__(*args, **kwargs):
		Exception.__init__(*args, **kwargs)

class Generator():
	def __init__(self):
		self.PREFIX = bytes.fromhex("19")
		self.SIG_KEY = bytes.fromhex("DFA5ED192DDA6E88A12FE12130DC6206B1251E44")
		self.DEVICE_KEY = bytes.fromhex("E7309ECC0953C6FA60005B2765F99DBBC965C8E9")


	def signature(self, data: Union[str, bytes]):
		data = data if isinstance(data, bytes) else data.encode("utf-8")
		return b64encode(self.PREFIX + new(self.SIG_KEY, data, sha1).digest()).decode("utf-8")


	def generate_device_id(self):
		ur = self.PREFIX + (urandom(20))
		mac = new(self.DEVICE_KEY, ur, sha1)
		return f"{ur.hex()}{mac.hexdigest()}".upper()

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
		return {
			"device_id": self.generate_device_id(),
			"user_agent": "Apple iPhone12,1 iOS v15.5 Main/3.12.2"
		}

class headers():
	def __init__(self, data = None, content_type = None, deviceId: str = None, sid: str = None):
		self.device = Generator().deviceId()
		self.User_Agent = self.device["user_agent"]
		self.sid = sid
		if deviceId!=None:self.device_id = deviceId
		else:self.device_id = self.device["device_id"]


		self.headers = {
			"NDCDEVICEID": self.device_id,
			"NDCLANG": "ru",
			"Accept-Language": "ru-RU",
			"SMDEVICEID": "20230109055041eecd2b9dd8439235afe4522cb5dacd26011dba6bbfeeb752", 
			"User-Agent": self.User_Agent,
			"Content-Type": "application/json; charset=utf-8",
			"Host": "service.narvii.com",
			"Accept-Encoding": "gzip",
			"Connection": "Upgrade"
		}


		if data is not None:
			self.headers["Content-Length"] = str(len(data))
			self.headers["NDC-MSG-SIG"] = Generator().signature(data=data)

		if self.sid is not None:self.headers["NDCAUTH"] = f"sid={self.sid}"

		if content_type is not None:self.headers["Content-Type"] = content_type

class AminoClient:
	def __init__(self, proxies = None, deviceId: str = None):
		self.api = "https://service.narvii.com/api/v1"
		self.proxies = proxies
		self.uid = None
		self.sid = None
		self.deviceId = None
		self.session = Session()
		if deviceId:self.deviceId=deviceId
		self.session_async=ClientSession()


	def __del__(self):
		try:
			loop = get_event_loop()
			loop.create_task(self._close_session())
		except RuntimeError:
			loop = new_event_loop()
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

		async with self.session_async.post(f"{self.api}/x{comId}/s/community/stats/user-active-time",headers=self.parser(data=data), data=data, proxy=self.proxies) as response:
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
		async with self.session_async.post(url, headers=self.parser(data=data), data=data, proxy=self.proxies) as response:
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
		elif api_code == 200:raise PasswordError(data)
		else:raise Exception(data)


class App():
	def __init__(self):
		self.error_color = fore.RED
		self.successful_color = fore.GREEN
		self.regular_color = fore.GREY_63
		self.input_color = fore.DEEP_SKY_BLUE_2
		self.email=None
		self.start()

	def start(self):
		loop = new_event_loop()
		set_event_loop(loop)
		loop.run_until_complete(self.mainProcess())



	async def send(self, client):
		coins = client.get_wallet_info()['totalCoins']
		try:
			if coins > 500:
				for _ in range(coins // 500):await client.send_coins(comId=self.comId, coins=500, blogId=self.blogId)
			if coins:await client.send_coins(comId=self.comId, coins=coins % 500, blogId=self.blogId)
		except Exception as ex:print(ex)
		print(self.successful_color,f"Sent {coins} coins.".upper(),self.regular_color)


	def TZ(self):
		localhour = strftime("%H", gmtime())
		localminute = strftime("%M", gmtime())
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



	def timers(self):return [{'start': int(timestamp()), 'end': int(timestamp()) + 300} for _ in range(50)]

	def date_now(self): return str(datetime.now()).split(" ")[0].replace("-", ".")

	def time_now(self): return str(datetime.now()).split(" ")[1].split(".")[0]

	def create_time(self): return f'{self.date_now()} - {self.time_now()}'


	def getLink(self, client):
		try:
			self.linkInfo = client.get_from_link(self.url)
			self.comId = self.linkInfo['extensions']['linkInfo']['ndcId']
			self.blogId = self.linkInfo['extensions']['linkInfo']['objectId']
		except Exception as error:print(self.error_color,f'Failed to retrieve information from link:\n{error}'.upper(),self.regular_color);self.getLink()


	async def mainProcess(self):
		system('cls || clear')
		print(f"""{self.error_color}

		╭━━━┳━━━┳━━┳━╮╱╭┳━━━┳━━━┳━╮╱╭╮
		┃╭━╮┃╭━╮┣┫┣┫┃╰╮┃┃╭━╮┃╭━━┫┃╰╮┃┃
		┃┃╱╰┫┃╱┃┃┃┃┃╭╮╰╯┃┃╱╰┫╰━━┫╭╮╰╯┃
		┃┃╱╭┫┃╱┃┃┃┃┃┃╰╮┃┃┃╭━┫╭━━┫┃╰╮┃┃
		┃╰━╯┃╰━╯┣┫┣┫┃╱┃┃┃╰┻━┃╰━━┫┃╱┃┃┃
		╰━━━┻━━━┻━━┻╯╱╰━┻━━━┻━━━┻╯╱╰━╯

		MADE BY Xsarz (Telegram -> @DXsarz)

		GitHub: https://github.com/xXxCLOTIxXx
		Telegram channel: https://t.me/DxsarzUnion
		YouTube: https://www.youtube.com/channel/UCNKEgQmAvt6dD7jeMLpte9Q
		Discord server: https://discord.gg/GtpUnsHHT4

		{self.regular_color}\n""")
		try:accounts = open("accounts.txt").read().split('\n');shuffle(accounts)
		except FileNotFoundError:print(self.error_color,'accounts.txt',' not found, create this file and add accounts there.'.upper(),self.regular_color);return
		self.url = input(f"\n{self.input_color}Post Link #~ {self.regular_color}")
		while True:
			try:
				bot_acc = accounts[0]
				accounts.remove(bot_acc);accounts.append(bot_acc)
				email, password, deviceId = bot_acc.split(" ")
				self.email=email
				client = AminoClient(deviceId=deviceId)
				client.login(email, password)
				print(self.successful_color,f"{email} Authorized.".upper(),self.regular_color)
				self.getLink(client)
				try:client.join_community(self.comId)
				except:pass
				try:
					for _ in range(1, 25):
						await client.send_active_obj(comId=self.comId, timers=self.timers(), tz=self.TZ())
						print(f" {self.input_color}[{self.error_color}{self.email}{self.input_color}]Sent {str(_)} ACTIVE-OBJ out of 24.{self.regular_color}")
						sleep(2.5)
				except AccountLimitReached or TooManyRequests:pass
				except InvalidRequest:print(self.error_color,f"Invalid request. -> {self.email}.".upper(),self.regular_color)
				await self.send(client=client)


			except AccountLimitReached or TooManyRequests:print(self.error_color,f"Too many requests -> {self.email}.".upper(),self.regular_color);continue
			except AccountDisabled:print(self.error_color,f"Account disabled (banned) -> {self.email}.".upper(),self.regular_color);continue
			except ActionNotAllowed:print(self.error_color,f"Action not allowed -> {self.email}.".upper(),self.regular_color);continue
			except IpTemporaryBan:print(self.error_color,f"Banned by ip (403), the process will be restored in 360 seconds -> {self.email}.".upper(),self.regular_color);sleep(360);continue
			except PasswordError: print(self.error_color,f"Incorrect password -> {self.email}.".upper(),self.regular_color);sleep(3);continue
			except Exception as error:print(self.error_color,f"Error -> {self.email}:\n{error}\n".upper(),self.regular_color);continue




if __name__ == '__main__':
	App()
