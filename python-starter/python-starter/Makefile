all: c0_serve

default: all

c0_serve:
	install ./c0_serve.sh $@

clean:
	rm -f c0_serve lab2.zip

SRC_DIRS := ./src
VENDOR_DIRS := ./vendor
GITIGNORE_FILE := $(shell test -f .gitignore && echo .gitignore)

FILES := \
	Makefile \
	requirements.txt \
	$(GITIGNORE_FILE) \
	c0_serve.sh \
	$(shell find $(SRC_DIRS) -name '*.py') \
	$(shell test -d $(VENDOR_DIRS) && find $(VENDOR_DIRS) -type f)

handin: lab2.zip

lab2.zip: $(FILES)
	zip $@ $^

.PHONY: clean handin
