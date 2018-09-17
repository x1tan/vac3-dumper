## vac3-dumper

**Dump VAC3 modules while playing a VAC-secured game on Linux.**

> $ cargo build --release  
> $ cd target/release  
> $ sudo ./vac3-dumper  

**Always run with root privileges!**

Start a VAC-secured game of your choice and join a server. As soon as VAC3 modules are loaded and manually mapped into 
the game process they are additionally dumped to the current folder.

Typically there will be multiple modules which are loaded at different at different times. Therefore it is recommended to 
start the dumper before you start the actual game and leave it running while playing.

**Beware: the dumper does not prevent the modules from being loaded (otherwise you could not join a VAC-secured server) therefore
do not run any third party applications which may get you banned (e.g. hacks).**

**Furthermore, althought the dumper is currently not detected and does not modify the VAC-secured game at all, do not use 
this tool on an account which you are not willed to get banned. Use at your own risk.**

**Make sure to restart Steam and the game afterwards!**

> $ kill $(pidof steam csgo_linux64))

