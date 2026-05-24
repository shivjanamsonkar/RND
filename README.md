# RND
R&D on listener side in C, so that it could be run in POS devices

For a full **build → run → verify → production** walkthrough, see [LAUNCH.md](LAUNCH.md).

step to run.
1. compile the listener.c by typing gcc listener.c -o listener
2. run the listener file by ./listener
3. telnet 127.0.0.1 8080 using command prompt
4. type message and press enter
5. listener will shows that message on screen.
