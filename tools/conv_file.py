#!/usr/bin/python

import sys

def parse(filename):
	fo = open(filename, "r")
	while True:
		line = fo.readline()
		if not line:
			break;

		if line.startswith('//'):
			continue

		items = line.strip("\r\n").split('\t')
		if len(items) < 2:
			continue
		if not items[0]:
			continue
		if not items[1]:
			continue

		print('\t%s, %s,' % (items[0].strip(), (items[1].split())[0].strip()))
	fo.close()

if __name__ == "__main__":
	if len(sys.argv) == 2:
		parse(sys.argv[1])
