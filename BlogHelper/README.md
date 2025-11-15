# Hugo 博客发布工具 Pro

增强版的博客发布工具，带有美观的界面和强大的功能。

## 安装依赖

```bash
pip install -r requirements.txt
```

## 运行

### 脚本方式运行
```bash
python blog_publisher_pro.py
```

### 打包为exe（推荐）
```bash
# 方式1: 使用提供的批处理脚本
build.bat

# 方式2: 手动打包
pip install pyinstaller
pyinstaller --onefile --windowed --name="BlogPublisherPro" blog_publisher_pro.py
```

打包后的 exe 文件在 `dist` 目录下。

程序会自动请求管理员权限。

## 功能特性

1. **美观的界面** - 使用 ttkbootstrap 深色主题
2. **历史记录** - 自动保存每次发布，可随时加载、删除
3. **智能标签** - 自动记录标签使用频率，智能推荐
4. **Markdown预览** - 支持源码和渲染两种预览模式
5. **彩色日志** - 不同操作结果显示不同颜色
   - 绿色：成功
   - 红色：错误
   - 黄色：警告
   - 蓝色：信息
   - 白色：一般输出

## 界面布局

### 左侧 - 编辑区
- 编辑文章：标题、日期、标签、提交说明、Markdown内容

### 右侧 - 工具区（3个标签页）
- 历史记录：查看、加载、删除历史发布
- 日志：彩色实时日志输出
- 标签库：所有常用标签展示（网格布局，点击添加）

## 数据文件

- `blog_history.json` - 历史记录（最多保存50条）
- `tags_stats.json` - 标签使用统计

**注意**：打包为exe后，这些文件会保存在exe同目录下。
