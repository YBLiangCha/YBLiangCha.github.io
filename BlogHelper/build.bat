@echo off
echo 开始打包博客发布工具...
echo.

REM 检查是否安装了pyinstaller
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo 未检测到 pyinstaller，正在安装...
    pip install pyinstaller
)

echo.
echo 正在打包...
pyinstaller --onefile ^
    --windowed ^
    --name="BlogPublisherPro" ^
    --icon=NONE ^
    --add-data "blog_history.json;." ^
    --add-data "tags_stats.json;." ^
    blog_publisher_pro.py

echo.
echo 打包完成！
echo 可执行文件位置: dist\BlogPublisherPro.exe
echo.
pause
