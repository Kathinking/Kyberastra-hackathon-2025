@echo off
set TARGET=11.12.14.107

for /L %%i in (1,1,25) do (
    start "Ping %%i" cmd /k ping -t -l %TARGET%
)
    