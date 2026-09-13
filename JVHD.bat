@echo off
rem ============================================================
rem  JVHD Desktop (Windows)
rem  Chay bang cach double-click vao file nay.
rem  Yeu cau: Node.js LTS da cai san. Neu chua cai:
rem           https://nodejs.org/
rem
rem  Neu khong chay duoc, dung JVHD-debug.bat de xem loi.
rem ============================================================
cd /d "%~dp0"

rem --- kiem tra Node.js ---
where node >nul 2>nul
if errorlevel 1 goto NODE_MISSING

rem --- cai Electron lan dau neu chua co ---
if exist "node_modules\electron\dist\electron.exe" goto RUN
echo.
echo  [JVHD] Dang cai Electron lan dau. Vui long doi vai phut...
echo  (Can ket noi internet. Chi mat 1 lan dau tien.)
echo.
call npm install
if errorlevel 1 goto INSTALL_FAIL

:RUN
echo.
echo  [JVHD] Dang khoi dong...
echo  Dang cho xuat hien cua so JVHD. Dong cua so do de thoat.
echo.
call node_modules\.bin\electron.cmd . > "%~dp0jvhd.log" 2>&1
echo.
echo  [JVHD] Da dong. Xem chi tiet trong file jvhd.log neu can.
echo.
pause
exit /b 0

:NODE_MISSING
echo.
echo  [LOI] Khong tim thay Node.js tren may.
echo  Hay cai Node.js LTS truoc:  https://nodejs.org/
echo  Sau khi cai, mo lai JVHD.bat.
echo.
pause
exit /b 1

:INSTALL_FAIL
echo.
echo  [LOI] Cai Electron that bai (loi trong qua trinh npm install).
echo  - Kiem tra ket noi internet.
echo  - Neu dung proxy/firewall, xem huong dan cai trong README.md.
echo.
pause
exit /b 1
