.PHONY: all
all:
	# nothing to build

.PHONY: test
test:
	python3 -m unittest discover -s src -p *_test.py
