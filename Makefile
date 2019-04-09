all:
	python3 -m pip install hashlib --user
	python3 -m pip install json --user


run : 
	python3 src/node.py
