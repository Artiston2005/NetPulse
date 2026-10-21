@echo off
title Build NetPulse
cd /d "%~dp0"
echo Configuring NetPulse build...
cmake -B build -G "Ninja" -DCMAKE_CXX_COMPILER="C:/msys64/ucrt64/bin/g++.exe" -DCMAKE_C_COMPILER="C:/msys64/ucrt64/bin/gcc.exe" -DCMAKE_MAKE_PROGRAM="C:/msys64/ucrt64/bin/ninja.exe"
if %errorlevel% neq 0 (
    echo CMake configuration failed!
    pause
    exit /b %errorlevel%
)
echo Building NetPulse executable...
cmake --build build
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b %errorlevel%
)
echo Copying runtime DLLs...
copy /Y C:\msys64\ucrt64\bin\glfw3.dll build\ >nul
copy /Y C:\msys64\ucrt64\bin\libgcc_s_seh-1.dll build\ >nul
copy /Y C:\msys64\ucrt64\bin\libwinpthread-1.dll build\ >nul
copy /Y C:\msys64\ucrt64\bin\libstdc++-6.dll build\ >nul
echo Build succeeded! You can launch the application with run.bat.
pause
