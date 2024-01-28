.PHONY: all

OPENSSL_INCLUDE="/home/cfc4n/project/ecapture/deps/openssl/include"
OPENSSL_PATH="/home/cfc4n/project/ecapture/deps/openssl"

SDL_LIB = -L$(OPENSSL_PATH) -lcrypto -lssl
SDL_INCLUDE = -I$(OPENSSL_INCLUDE)
CXXFLAGS = -Wall -c -std=c++11 $(SDL_INCLUDE)
LDFLAGS = $(SDL_LIB)

CFLAGS=$(SDL_INCLUDE)

EXE = test_tls_client

all: $(EXE)

$(EXE): main.o
	$(CXX) $< $(LDFLAGS) -o $@

main.o: main.c
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm *.o && rm $(EXE) | exit 0
