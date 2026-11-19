.PHONY: run build test race vet tidy clean

run:
	$(MAKE) -C core run

build:
	$(MAKE) -C core build

test:
	$(MAKE) -C core test

race:
	$(MAKE) -C core race

vet:
	$(MAKE) -C core vet

tidy:
	$(MAKE) -C core tidy

clean:
	$(MAKE) -C core clean
