#coding=utf-8
from capstone import *

WinStatus_dic = {}

with open("WinStatus.txt", "r") as file:
	for line in file:
		splitlist = line.split(' ', 5)
		key = splitlist[0]
		val = splitlist[1]
		WinStatus_dic[val] = key

file.close()


while True:
	try:
		Status = input('Enter Status Num>> ')
		formatted_string = "{} -> {}".format(Status, WinStatus_dic[Status])
		print(formatted_string)
	except:
		print("error :(")

