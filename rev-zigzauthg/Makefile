.PHONY: main, clean

main: src/main.zig
	- zig build-exe src/main.zig
	- strip --strip-debug main
	- mv main zigzauthg

clean:
	- rm -f *.o
	- rm zigzauthg
