
all:
	python3 -m pip install ecdsa --user 

run : 
	python3 src/main.py
clean:
	rm -f blocks/*
	rm -f TxPool/*
