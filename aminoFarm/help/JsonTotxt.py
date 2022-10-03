import json

with open(input("File name >>")+".json", "r") as file:
    accounts: list = json.load(file)

accounts = [f'{account["email"]} {account["password"]} {account["device"]}' for account in accounts]

with open("accounts.txt", "w") as file:
    file.write("\n".join(accounts))
