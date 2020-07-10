import os,datetime

FILEN = 'log.log'

def init(filename,isDel):
	if os.path.isfile(filename) == False:
		open(filename,'w+')
	else:
		if isDel == True:
			os.remove(filename)
			open(filename,'w+')
	global FILEN
	FILEN = filename

def log(output):
	Thetime = datetime.datetime.now().strftime('%Y-%m-%d  %H:%M:%S')
	file = open(FILEN,'a')
	file.write('<'+Thetime+'># '+output+'\n')