CXXFLAGS += -std=c++20 -O2 -fPIC -shared -Wall
INCLUDES = -I./include
LDFLAGS += -lcrypto

SRC = chat-module.cc websocket-accept.cc
TARGET = libchat.so

ENVOY := /usr/local/bin/envoy-1.40.2-linux-x86_64 
all: $(TARGET)

run: $(TARGET)
	ENVOY_DYNAMIC_MODULES_SEARCH_PATH=. $(ENVOY) -c envoy.yaml

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(INCLUDES) $(SRC) -o $(TARGET)

clean:
	rm -vf $(TARGET)

.PHONY: all clean
