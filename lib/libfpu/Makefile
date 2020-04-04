OUTPUT := libfpu.so

all: $(OUTPUT)

clean:
	@rm -rf $(OUTPUT)

$(OUTPUT): fpu.c
	@$(CC) -O3 -shared -fPIC $< -o$@

.PHONY: clean
