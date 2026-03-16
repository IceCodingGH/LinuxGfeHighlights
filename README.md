# LinuxGfeHighlights
# Proton/Wine NVIDIA Highlights -> gpu-screen-recorder bridge

This repo contains:
- sourcecode for a mocked `GfeSDK.dll` shim for Wine/Proton that reports NVIDIA Highlights via UDP
- a Linux UDP listener that receives highlight events and runs a replay-save command.

## Files

- `gfe_shim/GfeSDK.c`: Windows DLL shim source.
- `gfe_shim/GfeSDK.def`: exported symbols.
- `gfe_shim/Makefile`: build helper.
- `bridge/highlight_listener.sh`: Linux event listener.


## 1) Build the mock DLL

Install MinGW cross compiler first (package name depends on distro).

Debian: 
sudo apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 wine64

Build:

```bash
cd gfe_shim
make
```

Output:
- `build/GfeSDK.dll`

## 2) Put the mocked dll where the game loads `GfeSDK.dll`

Copy `build/GfeSDK.dll` to the game directory and replace existing file. 

Then adjust Steam launch options and replace <user> with Linux User Home Directory :

```bash
GFE_SHIM_SEND_UDP=1 GFE_SHIM_LOG_FILE="Z:\\home\\<user>\\gfe_shim.log" %command%
```

## 3) Start gpu-screen-recorder

The following assumes you installed gpu-screen-recorder via flatpak
Adjust Parameters to your format and output folder 

```bash
flatpak run --command=gpu-screen-recorder com.dec05eba.gpu_screen_recorder -w DP-1 -f 60 -a "default_output" -c mkv -r 60 -o /home/<user>/Videos
```

## 4) Start Linux listener

The listener receives UDP messages on `127.0.0.1:31337`.
Default action is for saving replays

```bash
highlight_listener.sh
```

Env variables can be set to overwrite, delay (HIGHLIGHT_ASYNC_DELAY_SEC), save Signal to gpu-screen-recorder (GSR_SAVE_CMD)


## Notes

- Tested with MK11, Uncharted Legacy of Thieves, Shadow of the Tomb Raider under Debian 13 with GE_Proton
- This is a proof-of-concept no finished work.
- Some anti-cheat systems may treat this as tampering. Avoid for protected online play.

