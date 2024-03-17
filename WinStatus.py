#coding=utf-8

WinStatusVal_STATUS = {}
WinSTATUS_StatusVal = {}

with open("WinStatus.txt", "r") as file:
	for line in file:
		SplitList = line.split(' ', 5)
		STATUS = SplitList[0]
		StatusVal = SplitList[1]
		WinSTATUS_StatusVal[STATUS] = StatusVal
		WinStatusVal_STATUS[StatusVal] = STATUS
file.close()

while True:
	while True:
		try:
			StatusVal = input('Enter Status Val (Enter quit to return)>> ')
			if StatusVal == 'quit':
				break
			formatted_string = "{} -> {}".format(StatusVal, WinStatusVal_STATUS[StatusVal])
			print(formatted_string)
		except:
			print("Error :(")
	while True:
		try:
			STATUS = input('Enter Status String (Enter quit to return)>> ')
			if STATUS == 'quit':
				break
			formatted_string = "{} -> {}".format(STATUS, WinSTATUS_StatusVal[STATUS])
			print(formatted_string)
		except:
			print("Error :(")
