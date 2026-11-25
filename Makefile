BUILD_DIR ?= build
CMAKE ?= cmake
SUDO ?= sudo

.PHONY: all configure test clean install uninstall

all: configure
	$(CMAKE) --build "$(BUILD_DIR)" --parallel

configure:
	$(CMAKE) -S . -B "$(BUILD_DIR)" -DCMAKE_BUILD_TYPE=Release

test: all
	ctest --test-dir "$(BUILD_DIR)" --output-on-failure

clean:
	$(CMAKE) -E rm -rf "$(BUILD_DIR)"

install: all
	$(SUDO) ./install.sh

uninstall:
	$(SUDO) ./uninstall.sh
